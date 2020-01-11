import click, os, pick, re, tabulate
from funcy import identity
from .libs.classproperties import Mappings, Snort, BColor

# Instantiate Mappings() class for future functions
m = Mappings()


def process_rules():
    # Call Mapping() open_file class method to obtain the Src files generator, ready for iteration
    file_generator = m.open_file()
    # Regex pattern to pull out the values needed to initialise the Snort() class
    snort_re_pattern = r'(?<=msg:")[^";]*(?=";)|(?<=classtype:)[\w-]*(?=;)|(?<=sid:)\d*(?=;)|(?<=rev:)\d*(?=;)'
    snort_cve_re_pattern = r'(?<=cve,)[\d-]*(?=;)'
    for rule in file_generator:

        cve = []

        if re.search(snort_cve_re_pattern, rule):
            cve = re.findall(snort_cve_re_pattern, rule)

        # Disabled rules code execution
        if rule.startswith("# alert"):
            msg, classtype, sid, rev = re.findall(snort_re_pattern, rule)
            s = Snort(state="disabled", msg=msg, classtype=classtype, sid=sid, rev=rev, full_rule=rule)

            if cve:
                s.cve = cve

            m.import_classifications(s.classtype)
            m.generate_initial_statistics(action="disabled")
            m.rules.append(s)

            # Add metrics for disabled rules as they are being imported and instantiated
            if s.classtype in m.metrics['counts'].keys():
                m.metrics['counts'][s.classtype] += 1
            else:
                m.metrics['counts'][s.classtype] = 1
        
        # Enabled rules code execution
        elif rule.startswith("alert"):
            msg, classtype, sid, rev = re.findall(snort_re_pattern, rule)
            s = Snort(state="active", msg=msg, classtype=classtype, sid=sid, rev=rev, full_rule=rule)

            if cve:
                s.cve = cve
            
            m.import_classifications(s.classtype)
            m.generate_initial_statistics(action="enabled")
            m.rules.append(s)

            # Add metrics for enabled rules as they are being imported and instantiated
            if s.classtype in m.metrics['counts'].keys():
                m.metrics['counts'][s.classtype] += 1
            else:
                m.metrics['counts'][s.classtype] = 1


def modify_rules():
    # Set Title and Options, ready for pick multi-selection function
    title = 'Please choose your classtype (press SPACE to mark, ENTER to continue): '
    options = []
    # Load in classifications with count metrics
    [options.append(f'{classification} | Count: {m.metrics["counts"][classification]} | Description: {m.classifications_desc[classification]}') for classification in m.classifications]
    # Load title and classification options into the pick function
    selected = pick.pick(options, title, indicator='->', multi_select=True, min_selection_count=1)
    # Remodel the selection to remove the previously added metrics and description - this allows the altering function to match precise classtypes
    selected = [selection[0].split(" | ")[0] for selection in selected]
    # Add the selections into the Mapping user options Set() - removes any potential duplicates
    [m.user_options.add(selection) for selection in selected]
    # Call Mappings class function to begin the rule alterations
    m.modify_rules()
    m.rules_modified = True


def create_file():

    if m.src_file == m.dst_file:
        os.rename(m.src_file, m.src_file + ".old")
        m.src_file = m.src_file + ".old"
        m.results_file()
    else:
        m.results_file()


def run_dashboard():

    # Print File Paths
    print(f"Source File: {m.src_file} | Destination File: {m.dst_file}")

    # Pre-Modification Table Stats
    print("\n")
    click.echo(click.style(tabulate.tabulate(
        [['Active', m.metrics['pre-modification']['active']],
         [f'{BColor.RED}Disabled{BColor.ENDC}', f"{BColor.RED}{m.metrics['pre-modification']['disabled']}{BColor.ENDC}"],
         [f'{BColor.BOLD}Total{BColor.ENDC}', f"{BColor.BOLD}{m.metrics['pre-modification']['total']}{BColor.ENDC}"]],
        headers=[f'{BColor.BOLD}Pre-Modification{BColor.ENDC}', ""], tablefmt='github'), fg='white'))
    print("\n")

    if m.rules_modified:
        # Post Modification Table Stats
        click.echo(click.style(tabulate.tabulate(
            [['Active', m.metrics['post-modification']['active']],
            [f'{BColor.RED}Disabled{BColor.ENDC}', f"{BColor.RED}{m.metrics['post-modification']['disabled']}{BColor.ENDC}"],
            [f'{BColor.BOLD}Total{BColor.ENDC}', f"{BColor.BOLD}{m.metrics['post-modification']['total']}{BColor.ENDC}"]],
            headers=[f'{BColor.BOLD}Post-Modification{BColor.ENDC}', ""], tablefmt='github'), fg='white'))
    print("\n")

    print(m.apps)


# CLI arg options and main process function
@click.command()
@click.option("--src", "-s", required=True,
    help="Local path to ids rule file to be processed.",
    type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--dst", "-d",
    help="[DEFAULT: if none selected, will append '.old' to src file, and replace with the dst file] Local path to the finalised rule file.",
    type=click.Path(dir_okay=False))
@click.option("--app-file", "-app",
    help="Path to the CSV holding a 2 column list (application_name,version) to enable rules on",
    type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--cve-file", "-cve",
    help="Path to the CSV holding a 1 column list (e.g. cve,2018-1111) to enable rules on",
    type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--verbose", is_flag=True, help="Verbose output")
def process(src, dst, app_file, cve_file, verbose):
    """ Processes the input rule file - allows the user to modify the rules via interactive classtype selection -
    and saves the new rules to an output rule file.
    """

    # verbose_print = print if verbose else identity
    # set filenames from arguments
    m.src_file = src
    if dst == None:
        m.dst_file = src[:]
    else:
        m.dst_file = dst

    if app_file:
        m.open_csv_file(app_file, input_type='apps')
    
    if cve_file:
        m.open_csv_file(cve_file, input_type='cve')

    process_rules()

    user_selection = ""

    while user_selection != "q":
        print("\nWelcome to the App, press 'q' to exit\n")
        print("1. View the rule dashboard?")
        print("2. Alter the rule sets?")
        if m.rules_modified:
            print("3. Create the new rule file?")
        user_selection = input("> ")
        
        if user_selection == "1":
            run_dashboard()
        elif user_selection == "2":
            modify_rules()
        elif user_selection == "3":
            create_file()
        elif user_selection == "q":
            break

if __name__ =="__main__":
    process()
