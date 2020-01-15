# idsparser

idsparser is a CLI based python tool for interactively enabling and disabling Snort based IDS rules. The tool can either be passed a single rule file (community rules), or a directory of rule files (subscriber based rules).

Additionally, the tool can also be passed CSV files of known applications in use on the network the rules will be monitoring, and CVEs typically identified via a vulnerability scanner. If these CSV files are passed in as options, any rules containing the CVEs or applications will be enabled automatically.

A user can then enable rules of a particular classtype e.g. denial-of-service, trojan-activity, etc via a multi-selection menu for ease of use.

The tool will then ouput the newly modified ruleset into a file organised into clear enabled/disabled sections, as well as identifying at the top which classtypes were chosen by the user.

## Usage

### Installation

### Launching

```bash
$ cd idsparser/
$ python3 -m idsparser
```

### Visual

![](idsparser-demo.gif)

## Roadmap

* Improve the flow and visual of the menu/dashboard

* Add the ability for a user to search for specific rules once the rule files have been loaded, and then to toggle between enabled/disable.

* If the src is a directory of rules (typically with subscriber based rule sets) then output the results in a similar fashion, so that large amount of rules are not contained in the same rule file.

* Add functionality for Suricata based rules.

## License
