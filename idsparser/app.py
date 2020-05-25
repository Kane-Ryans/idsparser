import click
import os
import pick
import re
import tabulate
from funcy import identity
from .libs.classproperties import Mappings, Snort, BColor

# Instantiate Mappings() class for future functions
m = Mappings()

def source_file_check():
    # Check if user input is a directory or file, and call the appropriate open file class moethod
    if os.path.isdir(m.src_file):
        for file in os.listdir(m.src_file):
            if file.endswith('.rules'):
                file_generator = m.open_directory(file)
                process_rules(file_generator)
    elif os.path.isfile(m.src_file):
        file_generator = m.open_file()
        process_rules(file_generator)

def process_rules(file_generator):
    # Regex pattern to pull out the values needed to initialise the Snort() class
    snort_rule_check_pattern = r'^#\s(alert|drop|log|activate)|^(alert|drop|log|activate)'
    snort_re_pattern = r'(?<=msg:")[^";]*(?=";)|(?<=classtype:)[\w-]*(?=;)|(?<=sid:)\d*(?=;)|(?<=rev:)\d*(?=;)'
    snort_cve_re_pattern = r'(?<=cve,)[\d-]*(?=;)'
    for rule in file_generator:

        cve = []
        if re.search(snort_cve_re_pattern, rule):
            cve = re.findall(snort_cve_re_pattern, rule)

        if re.search(snort_rule_check_pattern, rule):
            msg, classtype, sid, rev = re.findall(snort_re_pattern, rule)
            s = Snort(state="disabled", msg=msg, classtype=classtype, sid=sid, rev=rev, full_rule=rule)
            m.import_classifications(s.classtype)

            if cve:
                s.cve = cve

            if rule.startswith('#'):
                # Disabled rules code execution
                m.generate_initial_statistics(action="disabled")
                m.rules.append(s)
            elif not rule.startswith('#'):
                # Enabled rules code execution
                s.state = "active"
                m.generate_initial_statistics(action="enabled")
                m.rules.append(s)

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
    # If no destination file specified, append source file with .old, so the new file can be created with the original name 
    if m.src_file == m.dst_file:
        os.rename(m.src_file, m.src_file + ".old")
        m.src_file = m.src_file + ".old"
        m.results_file()
    else:
        m.results_file()


def run_dashboard(cve_file, app_file):
    # Print File Paths
    click.echo(click.style('Filenames:', bold=True))
    click.echo(click.style(f'Source File: {m.src_file}', fg='green'))
    click.echo(click.style(f'Destination File: {m.dst_file}', fg='green'))
    # Print only if the user has imported App or CVE CSV files
    if cve_file and app_file:
        click.echo(click.style('Additionally:', bold=True))
        click.echo(click.style(f' # {len(m.cves)} CVEs have been loaded', fg='green'))
        click.echo(click.style(f' # {len(m.apps)} Apps have been loaded', fg='green'))
    elif cve_file:
        click.echo(click.style('Additionally:', bold=True))
        click.echo(click.style(f' # {len(m.cves)} CVEs have been loaded', fg='green'))
    elif app_file:
        click.echo(click.style('Additionally:', bold=True))
        click.echo(click.style(f' # {len(m.apps)} Apps have been loaded', fg='green'))
    print('-' * 10)

    print("\n")
    if not m.rules_modified:
        # Pre-Modification Table Stats 
        click.echo(click.style(tabulate.tabulate(
            [['Active', m.metrics['pre-modification']['active']],
            [f'{BColor.RED}Disabled{BColor.ENDC}', f"{BColor.RED}{m.metrics['pre-modification']['disabled']}{BColor.ENDC}"],
            [f'{BColor.BOLD}Total{BColor.ENDC}', f"{BColor.BOLD}{m.metrics['pre-modification']['total']}{BColor.ENDC}"]],
            headers=["", 
            f'{BColor.BOLD}Pre-Modification{BColor.ENDC}'], 
            tablefmt='github'), fg='white'
        ))
    else:
        # Post Modification Table Stats
        click.echo(click.style(tabulate.tabulate(
            [['Active', m.metrics['pre-modification']['active'],m.metrics['post-modification']['active']],
            [f'{BColor.RED}Disabled{BColor.ENDC}', f"{BColor.RED}{m.metrics['pre-modification']['disabled']}{BColor.ENDC}", f"{BColor.RED}{m.metrics['post-modification']['disabled']}{BColor.ENDC}"],
            [f'{BColor.BOLD}Total{BColor.ENDC}', f"{BColor.BOLD}{m.metrics['pre-modification']['total']}{BColor.ENDC}", f"{BColor.BOLD}{m.metrics['post-modification']['total']}{BColor.ENDC}"]],
            headers=["", 
            f'{BColor.BOLD}Pre-Modification{BColor.ENDC}',
            f'{BColor.BOLD}Post-Modification{BColor.ENDC}'],
            tablefmt='github'), fg='white'
        ))
    print("\n")
    # Print post processing stats - user classtypes selected, the number of rules matching imported apps and cves
    if m.user_options:
        click.echo(click.style("Classtype's Selected:", bold=True))
        click.echo(click.style(f'{", ".join(m.user_options)}'))
        if app_file:
            click.echo(click.style(f'Rules matching imported Apps: {m.metrics["matched-apps"]}', bold=True))
        if cve_file:
            click.echo(click.style(f'Rules matching imported CVEs: {m.metrics["matched-cves"]}', bold=True))

# CLI arg options and main process function
@click.command()
@click.option("--src", "-s", required=True,
    help="Local path to ids rule file to be processed.",
    type=click.Path(exists=True, dir_okay=True, readable=True))
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

    source_file_check()

    user_selection = ""

    user_options = {
        '1': modify_rules,
        '2': create_file
    }

    errmsg = None

    while user_selection != "q":
        os.system('clear')
        click.echo(click.style(r"""
    ____ ____  _____    ____                                
   /  _// __ \/ ___/   / __ \ ____ _ _____ _____ ___   _____
   / / / / / /\__ \   / /_/ // __ `// ___// ___// _ \ / ___/
 _/ / / /_/ /___/ /  / ____// /_/ // /   (__  )/  __// /    
/___//_____//____/  /_/     \__,_//_/   /____/ \___//_/     

        """, fg='green'))
        run_dashboard(cve_file, app_file)
        print('-' * 10)
        click.echo(click.style("\nWelcome to the App | Enter the menu option number to continue OR enter 'q' to quit\n", bold=True))
        # Will show an error message above the menu selection if populated, once printed errmsg will be set back to None so it isn't shown after a valid selection
        if errmsg != None:
            click.echo(click.style(f"{errmsg}", bold=True, fg='red'))
            errmsg = None
        print('-' * 10)
        print("1. Modify Rule Set via Classtype Selection")
        print("2. Create File")
        print('-' * 10)
        user_selection = input("> ")
        if user_selection in user_options.keys():
            # Display error if user tries to create a file when no modifications have been made
            if user_selection == '2' and not m.rules_modified:
                errmsg = 'No changes have been made. Please make changes before attempting to generate a new rule set file'
                continue

            user_options[user_selection]()

            if user_selection == '2':
                os.system('clear')
                click.echo(click.style(f'New ruleset created, and stored at: {m.dst_file}', bold=True))
                break
        elif user_selection == "q":
            os.system('clear')
            click.echo(click.style('Goodbye!', bold=True))
            break
        else:
            errmsg = 'Please enter a valid option'
        

if __name__ == "__main__":
    process()
