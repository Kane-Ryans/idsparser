import os
import pkg_resources

# Class for holding the rule objects and general logic for importing/exporting and altering the rule files
class Mappings:
    def __init__(self):
        self.rules = []
        self.classifications = set()
        self.classifications_desc = {}
        self.user_options = set()
        self.apps = set()
        self.cves = set()
        self.rules_modified = False
        self.src_file = ""
        self.dst_file = ""
        self.metrics = {
            "pre-modification": {
                "active": 0,
                "disabled": 0,
                "total": 0
            },
            "post-modification": {
                "active": 0,
                "disabled": 0,
                "total": 0
            },
            "matched-apps": 0,
            "matched-cves": 0,
            "counts": {}
        }
        self.import_classification_desc()
    

    def import_classification_desc(self):
        # On class initialisation, open classification file (if found) and ready the descriptions
        try:
            path = pkg_resources.resource_filename(__name__,os.path.join(os.pardir, 'resources', 'snort_classifications.txt'))
            with open(path, 'r') as desc:
                content = (d for d in desc.readlines())
                for description in content:
                    if description.startswith("config"):
                        name = description.split(":")[1].split(",")[0].strip()
                        desc = description.split(",")[1]
                        self.classifications_desc[name] = desc
        except OSError as e:
            print(e)
    

    def open_file(self):
        try:
            with open(f'{self.src_file}', 'r') as snort:
                return (s for s in snort.readlines())
        except OSError as e:
            print(e)

    def open_directory(self, file):
        try:
            with open(os.path.join(self.src_file, file), 'r') as snort:
                return (s for s in snort.readlines())
        except OSError as e:
            print(e)

    def open_csv_file(self, filename, input_type):
        if input_type == 'apps':
            with open(filename, 'r', encoding='utf-8-sig') as f:
                for app in f.readlines():
                    new_app = app.split(',')[0].strip().lower()
                    self.apps.add(new_app)

        elif input_type == 'cve':
            with open(filename, 'r', encoding='utf-8-sig') as f:
                for cve in f.readlines():
                    if cve.startswith('cve,'):
                        new_cve = cve.split(",")[1].strip()
                        self.cves.add(new_cve)
                    else:
                        new_cve = cve.strip()
                        self.cves.add(new_cve)
            

    def results_file(self):
        """Create results file.
        
        If there is already a current file with the same name, the application will remove and replace with a new rule file"""

        if os.path.exists(self.dst_file):
            os.remove(self.dst_file)

        with open(self.dst_file, 'a') as f:
            # Prepare enabled section of results file
            f.write("\n\n# ** Enabled **\n\n")
            f.write(f"Filtered based on classifications: {', '.join(self.user_options)}\n\n")
            # Prepare generator for file write
            enabled_rules = (rule.full_rule for rule in self.rules if rule.state == "active")
            [f.writelines(rule) for rule in enabled_rules]
            f.write("\n\n# ** Disabled **\n\n")
            disabled_rules = (rule.full_rule for rule in self.rules if rule.state == "disabled")
            [f.writelines(rule) for rule in disabled_rules]


    # def __len__(self):
    #     return len(self.maps)

    # Not used anymore since the multi-selection function implementation. Keeping code for knowledge
    # def classification_exist(self, answers = []):
        # return true if all users classtype inputs exist
        # return all(answer in self.classifications for answer in answers)


    def generate_initial_statistics(self, action):
        """Generate initial statistics upon loading the source rule file"""

        if action == "enabled":
            self.metrics['pre-modification']['active'] += 1
            self.metrics['pre-modification']["total"] += 1
        elif action == "disabled":
            self.metrics['pre-modification']['disabled'] += 1
            self.metrics['pre-modification']["total"] += 1
   

    def import_classifications(self, classtype):
        """Save the classtypes found in the source file for later user use"""

        self.classifications.add(classtype)
    

    def modify_rules(self):
        # reset stats for rules after modification
        self.metrics['post-modification']['active'] = 0
        self.metrics['post-modification']['disabled'] = 0
        self.metrics['post-modification']['total'] = 0

        for rule in self.rules:
            if self.apps and rule.does_app_appear_in_rule_msg(self.apps):
                self.alter_rule(rule, state="enable")
                self.metrics['post-modification']['active'] += 1
                self.metrics['matched-apps'] += 1
            
            elif self.cves and rule.does_cve_exist(self.cves):
                self.alter_rule(rule, state="enable")
                self.metrics['post-modification']['active'] += 1
                self.metrics['matched-cves'] += 1

            elif rule.classtype in self.user_options:
                self.alter_rule(rule, state='enable')
                self.metrics['post-modification']['active'] += 1
            else:
                self.alter_rule(rule, state='disable')
                self.metrics['post-modification']['disabled'] += 1

        # Finish function with updating the total post-mod count with the final stats
        self.metrics['post-modification']['total'] = self.metrics['post-modification']['active'] + self.metrics['post-modification']['disabled']
  

    def alter_rule(self, rule, state):
        """Enable/Disable altering logic to be applied to rule being evaluated"""

        # if rule is disabled, then slice out the '# ' to enable
        if rule.state == "disabled" and state == 'enable':
            rule.full_rule = rule.full_rule[2:]
            rule.state = "active"
        # if rule is disabled, and the rule should stay disabled, then just return the rule
        elif rule.state == "disabled" and state == 'disable':
            pass
        # if rule is not disabled (no hash symbol), and state is to enable, then just return the rule
        elif not rule.state == "active" and state == 'enable':
            pass
        # if rule is not disabled (no hash symbol), and state is to disable, then prepend '# ' to disable
        elif rule.state == "active" and state == 'disable':
            rule.full_rule = "# " + rule.full_rule
            rule.state = "disabled"



# Class for holding important information of each rule into an object
class Snort:
    def __init__(self, state, msg, classtype, sid, rev, full_rule, cve = []):
        self.state = state
        self.msg = msg
        self.classtype = classtype
        self.sid = sid
        self.rev = rev
        self.full_rule = full_rule
        self.cve = cve

    def __getitem__(self, item):
         return item

    def __str__(self):
        return f"{self.msg} {self.classtype} {self.sid} {self.rev} {self.full_rule}"

    def __repr__(self):
        return f"<Snort msg={self.msg} classtype={self.classtype} sid={self.sid} rev={self.rev} full_rule={self.full_rule}"

    def does_cve_exist(self, external_cve_list):
        return any(cve in external_cve_list for cve in self.cve)

    def does_app_appear_in_rule_msg(self, external_app_list):
        return any(app.lower() in self.msg.lower() for app in external_app_list)


# Class for adding colors to the statistics dashboards
class BColor:
    """
    BColor printable colors in terminal
    """

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
