# PolicyCleanUp
Check Point PolicyCleanUp tool allows automatic cleanup of your policy based on hits count. The tool runs on a policy 
and a domain that you named.

*   If a rule was not hit for the number of days that you configured, the rule is a candidate to be disabled.
*   If a rule is disabled for the number of days that you configured, the rule is a candidate to be deleted.

You can adjust the code according to your organization’s policy / needs.

  - This tool can be executed on Management Server / Multi-Domain servers of version of R80.10 and up.

## Instructions
Clone the repository with this command:
```git
git clone https://github.com/CheckPointSW/PolicyCleanUp
``` 
or by clicking the _‘Download ZIP’_ button. 

Download and install the [Check Point API Python SDK](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk) 
repository, follow the instructions in the SDK repository.

## Main Options
*__More options and details can be found with the '-h' option by running:__ python policyCleanUp.py –h*
*   [--package &nbsp; ,&nbsp; -k]&emsp; The name of the policy package to clean from zero-hit rules. The default is all 
policies.
*   [--operation , -op]&emsp;   The operation mode in which the tool runs. The default is plan.
<br>&emsp;&emsp;There are 3 modes:<br>  
    *  plan: tool runs without performing changes in the policy. The output file is in Json format. The output file 
    holds rules that are candidates for deletion or to be disabled.
    *  apply: tool runs and makes changes in the policy. The rules are disabled and deleted according to the plan. 
    At the end of this operation, publish is executed.
    *  apply without publish: tool runs and makes changes but without publish. In this mode, 
    you can login from SmartConsole to this session and explore changes before they are published.
*   [--import-plan-file , -i]&emsp; A file that holds output of execution of the ‘plan’ operation. 
You can use this file only on apply or apply_without_publish operations. Tip: using this option saves time of the ‘apply’ 
operation if you already executed a ‘plan’.
*   [--disable-after]&emsp; Time in days in which if there are no hits, the rule is a candidate for disabling. 
Default is 180 days. Learn how to change the default in ‘Technical Details’ section.
*   [--delete-after]&emsp;  Time in days for a disabled rule to be a candidate for deletion. Only rules that 
were disabled by the tool are candidates for deletion. Default is 60 days. Learn how to change the default in ‘Technical 
Details’ section.
*   [--output-file]&emsp;   Name of the output file. The file is in Json format. This file helps you understand 
which rules were affected. If not supplied, the default file name is _‘policyCleanUp-<unix-timestamp>.json’_. 
To use it in ‘apply’ operations, pass it as 'import plan file'.

## Examples
*   Running the tool on a remote management server using username & password: 
<br>```python policyCleanUp.py  -m 172.23.78.160 -u James -p MySecretPassword!```
<br>The tool runs on a remote management server with IP address 172.23.78.160 and the operation is ‘plan’ (default).
*   Running the tool on a remote management server using API key: 
<br>```python policyCleanUp.py  -m 172.23.78.160 --api-key JpPA+eJ5gekQBY8DF27+ZQ==```
*   Running the tool on a Multi-Domain Server for a specific domain and a specific policy package: 
<br>```python policyCleanUp.py  -d 172.23.78.152 –k Standard -u James -p MySecretPassword!```
*   Running the tool on a Security Management Server with operation plan: 
<br>```python policyCleanUp.py  -o plan_output_file.json -op plan -u James -p MySecretPassword!```
<br>The tool runs in plan mode and creates a json output file named “plan_output_file.json” as noted. This file can 
    be used later on as an ‘import-plan-file’ for ‘apply’ mode.
*   Running the tool on a Security Management Server and applying the import-plan-file:
<br>```python policyCleanUp.py  -i plan_output_file.json  -op apply -u James -p MySecretPassword!```
<br>The tool runs in apply mode. Rules are disabled / deleted according to the import-plan-file “plan_output_file.json”._
*   Running the tool on a Security Management Server with operation apply-without-publish, set specific disable/deleted thresholds and session name:
<br>```python policyCleanUp.py -op apply_without_publish –-root true --disable-after 20 --delete-after 40 --session-name “Policy Cleanup script”```
<br>The tool runs in ‘apply without publish’ mode which means publish is not executed at the end but changes will be saved n private session.
You can connect to SmartConsole, find the session named “session_name” and explore the changes before publishing the session.<br>
This run will not use default thresholds but instead these are the thresholds:
<br>&emsp;- Disabled rules whose last hits were 20 days ago.
<br>&emsp;- Deleted rules which were disabled by the tool 40 days ago.

## Output
The tool’s output is a file in a Json format that holds the following information:
1.	List of packages that were scanned
<br>&emsp;- Each package holds its layers and installation targets
<br>&emsp;- Each layer in the package contains:
<br>&emsp;- disabled rules, deleted rules and skipped rules (and reason). 
<br>&emsp;- objects-dictionary (for rules)
2.	List of skipped packages with reasons
3.	Threshold values
4.	Operation mode in which the tool was ran

Example of Output:
```Git
{
    "operation": "plan", 
    "packages": [
        {
            "access-layers": [
                {
                    "delete-rules": {
                        "rules": [], 
                        "total": 0
                    }, 
                    "disable-rules": {
                        "rules": [...], 
                        "total": 7
                    }, 
                    "name": "Branch_Office_Policy Network", 
                    "objects-dictionary": [...], 
                    "shared": false, 
                    "skipped-rules": {
                        "rules": [...], 
                        "total": 3
                    }, 
                    "type": "access-layer", 
                    "uid": "13a747d1-7fda-483b-afca-f8d996a4a574"
                }, 
            ], 
            "installation-targets": [...], 
            "name": "Branch_Office_Policy", 
            "type": "package", 
            "uid": "89368746-46bd-418e-a625-2e848040c76f"
        }
    ], 
    "skipped-packages": [
        {
            "name": "Corporate_Policy", 
            "skipped-reason": "All package targets are invalid", 
            "type": "package", 
            "uid": "e187eb39-f6dd-4ee3-93c3-ce4df3e2e393"
        }
    ], 
    "thresholds": {
        "delete-after": 6, 
        "disable-after": 4
    }
}

```
If you run the tool with plan mode the output can be used as input for import-plan-file for the tool with apply/ apply without publish.  


## Technical Details
* The default values for‘--disable-after’ and ‘--delete-after’ are part of the python script (policyCleanUp.py). 
To change values, search for the following thresholds in code:
```python
# Defaults for global disable & delete thresholds
DEFAULT_DISABLE_THRESHOLD = 180
DEFAULT_DELETE_THRESHOLD = 60
```


* Relevant functions in the script that you can change to adjust the logic to your needs:
<br>&emsp;1.<i>‘apply_plan’</i> – a function that applies the changes per rule. If the rule was a candidate for disabling, it calls the ‘disable_rule’ function and if the rule candidate for deletion it calls the ‘delete_rule’ function. In both these functions the changes affect on the rule. 
<br>&emsp;2.<i>‘rule_should_be_disabled’</i> – a function that determines if rule should be disabled. A rule should be disabled if it’s last hit date or last modified date (the closest date) is before today’s date minus the threshold. The thresholds are determined by global thresholds or overrides thresholds.
<br>&emsp;3.<i>‘rule_should_be_deleted’</i> – a function that determines if a rule should be deleted. A rule should be deleted if the date it was disabled by the tool is before today’s date minus the threshold. The thresholds are determined by global thresholds or overrides thresholds
<br>&emsp;4.<i>‘validate_rule’</i> – a function that checks if the install-on list contains invalid target and that the rule was not modified after it was installed on targets.

* Example for a simple code adjustment:
<br>&emsp;<u>Objective:</u>  As part of rule disabling, set it to the bottom of the rulebase. 
<br>&emsp;<u>Solution:</u>
<br>&emsp;- Find ‘disable_rule’ function.
<br>&emsp;- Find the API call that disables the rule (‘set-access-rule’ command). 
<br>&emsp;- Add ‘new-position’ argument to existing command and set it to bottom.

<br>&emsp;&emsp;&emsp;Before:
```python
# Set rule changes
# *** If you wold like to your logic as part of rule disabling. This is the place ***
# *** For example: set rule position to bottom, you need add to API call 'new-position' parameter with value bottom.***
def disable_rule(rule, layer, api_client):
    global DATETIME_NOW
    global DATETIME_FORMAT

    # Disable rule & set disabled-time & add comment
    set_rule_res = api_client.api_call("set-access-rule",
                                       {"uid": rule['uid'], "layer": layer['uid'], "enabled": "false",
                                        "custom-fields": {"field-3": DATETIME_NOW.strftime(DATETIME_FORMAT)},
                                        "comments": rule['comments'] + " -This rule changed automatically by the policyCleanUp tool"})

    return not is_failure("    Failed to set rule No.{} with UID {}.".format(rule['rule-number'], rule['uid']), set_rule_res)

```
<br>&emsp;&emsp;&emsp;After:
```python
# Set rule changes
# *** If you wold like to your logic as part of rule disabling. This is the place ***
# *** For example: set rule position to bottom, you need add to API call 'new-position' parameter with value bottom.***
def disable_rule(rule, layer, api_client):
    global DATETIME_NOW
    global DATETIME_FORMAT

    # Disable rule & set disabled-time & add comment
    set_rule_res = api_client.api_call("set-access-rule",
                                       {"uid": rule['uid'], "layer": layer['uid'], "enabled": "false",
                                        "custom-fields": {"field-3": DATETIME_NOW.strftime(DATETIME_FORMAT)},
                                        "comments": rule['comments'] + " -This rule changed automatically by the policyCleanUp tool",
                                        "new-position": "bottom"})

    return not is_failure("    Failed to set rule No.{} with UID {}.".format(rule['rule-number'], rule['uid']), set_rule_res)

```

<b>Notice!</b> The tool uses the custom fields of rule (within SmartConsole - <i>Security Policies > Access Control > Policy > Summary tab</i>) 

## Development Environment
The tool is developed using Python language 2.7.14 and [Check Point API Python SDK](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk).




