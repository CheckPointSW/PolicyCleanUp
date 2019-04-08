#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""

policyCleanUp.py
version 1.1 (default in lib)

This tool gives a new utility, Automatic Cleanup Based On Hits utility, to streamline rule bases in a Multi-Domain Security Management environment.
The Automatic Cleanup Based On Hits Utility runs on a policy and domain that you name. It uses Hit Count


This tool demonstrates communication with Check Point Management server using Management API Library in Python.
Logout command is called automatically after the work with Management API Library is completed.

The output format will be similar to the output of show-packages command.
The report(disabled/deleted rules) will be under access-layers.disable-rules | .delete-rules

Use -h flag for details-usage.

written by: Check Point software technologies inc.
August 2018

"""


from __future__ import print_function
import argparse
import json
import time
import datetime

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# A package for reading passwords without displaying them on the console.
import getpass

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs

# Defaults for global disable & delete thresholds
DEFAULT_DISABLE_THRESHOLD = 180
DEFAULT_DELETE_THRESHOLD = 60

# Script running time in seconds
DATETIME_NOW = datetime.datetime.now().replace(microsecond=0)
DATETIME_NOW_SEC = int(round(time.mktime(DATETIME_NOW.timetuple())))
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DATETIME_NOW_STR = datetime.datetime.fromtimestamp(DATETIME_NOW_SEC).strftime(DATETIME_FORMAT)

# Default log file name
DEFAULT_OUTPUT_FILE_NAME = "policyCleanUp-{}.json".format(DATETIME_NOW_SEC)

# Global domain name
GLOBAL_DOMAIN_NAME = 'Global'

# Rule install-on all targets constant UID
INSTALL_ON_ALL_TARGETS = "6c488338-8eec-4103-ad21-cd461ac2c476"

REASON_OF_ALL_TARGETS_INVALID = "Check that Access policy is installed on all targets and " \
                             "policy wasn't modified after installation date and hitcount is active on targets"

# Parse user arguments
def parse_arguments():

    # Instantiate the parser
    parser = argparse.ArgumentParser(description='\nThis Is Check Point Automatic Cleanup Based On Hits Tool', formatter_class=argparse.RawTextHelpFormatter)

    # Optional list policies argument
    parser.add_argument('--package', '-k', help='\nName of the policy you want to disable & delete its rules. Default {ALL_POLICIES}', metavar="")

    # Optional operation argument
    parser.add_argument('--operation', '-op', choices=['plan','apply', 'apply_without_publish'], default='plan', metavar="\b",
                        help='{%(choices)s}\nplan: checking which rules will be disabled/deleted.\napply: disabling & deleting the rules.\n'+
                                'apply_without_publish: disabling & deleting the rules without publish.\nDefault {plan}')

    # Optional file argument
    parser.add_argument('--import-plan-file','-i', help='The name of json file. Apply the \'import-plan-file\' without re-run plan, should be provided in apply/apply_without_publish operations only', metavar="")

    # Optional management argument
    parser.add_argument('--management','-m', default='127.0.0.1', help='\nThe management server\'s IP address or hostname. Default {127.0.0.1}', metavar="")

    # Optional domain argument
    parser.add_argument('--domain','-d', help='\nThe name or uid of the Security Management Server domain.', metavar="")
    # Optional port argument
    # port is set to None by default, but it gets replaced with 443 if not specified (in lib)
    parser.add_argument('--port', help='\nPort of WebAPI server on management server. Default {443}', metavar="")

    # Optional user name argument
    parser.add_argument('--user','-u', dest='username', help='\nManagement administrator user name.', metavar="")

    # Optional password argument
    parser.add_argument('--password','-p', help='\nManagement administrator password.', metavar="")

    # Optional login as root argument
    parser.add_argument('--root', '-r', choices=['true', 'false'], help='\b{%(choices)s}\nLogin as root. When running on the management server, use this flag with value set to \'true\' to login as Super User administrator.', metavar=" \b\b")

    # Optional session name argument
    parser.add_argument('--session-name', help='\nSession unique name. Should be provided in apply/apply_without_publish operations only. Default {Policy_clean_up_tool}', default="Policy_clean_up_tool", metavar="")

    # Optional session description argument
    parser.add_argument('--session-description', help='Session description. Should be provided in apply/apply_without_publish operations only. Default {Current time}', default=DATETIME_NOW_STR, metavar="")

    # Optional delete threshold argument
    parser.add_argument('--delete-after', help='\nTime in days in which rule will be candidate for deletion.', default=DEFAULT_DELETE_THRESHOLD, metavar="")

    # Optional disable threshold argument
    parser.add_argument('--disable-after', help='\nTime in days in which rule will be candidate for disable.', default=DEFAULT_DISABLE_THRESHOLD, metavar="")

    # Optional output file argument
    parser.add_argument('--output-file','-o', default=DEFAULT_OUTPUT_FILE_NAME, metavar="",
                        help='\nName of the output Json file that help to understand which rules were affected. You can use it to apply etc as \'import plan file\'.\nDefault {policyCleanUp-<unix-timestamp>.json}')

    # Parse the arguments
    args = parser.parse_args()

    # Ask for username, password if needed & add customized logic to parsing
    customize_arguments(parser, args)

    return args

# Validate arguments from user - checks that the user has entered the required arguments and parsing
def customize_arguments(parser, args):

    # The user has not entered username
    if args.root is None:
        if args.username is None:
            if sys.version_info >= (3, 0):
                args.username = input("Username: ")
            else:
                args.username = raw_input("Username: ")

        # The user has not entered password
        if args.password is None:
            if sys.stdin.isatty():
                args.password = getpass.getpass("Password: ")
            else:
                print_msg("Attention! Your password will be shown on the screen!")
                if sys.version_info >= (3, 0):
                    args.password = input("Password: ")
                else:
                    args.password = raw_input("Password: ")

    # Plan-file should be provided in apply operations only
    if (args.import_plan_file is not None) and (is_apply_operation(args.operation) is False):
        print_msg("Error: plan-file should be provided in apply/apply_without_publish operations only.")
        exit(1)

    # Session-name and session-description should be provided in apply operations only
    if (is_apply_operation(args.operation) is False) and (is_default_session_details(args.session_name, args.session_description) is False):
        print_msg("Error: Session-name and Session-description should be provided in apply/apply_without_publish operations only.")
        exit(1)

    # If user inserted thresholds, update the "global" thresholds
    updateGlobalThreshold(args)

# Update global threshold
def updateGlobalThreshold(args):
    global DEFAULT_DISABLE_THRESHOLD
    DEFAULT_DISABLE_THRESHOLD = int(args.disable_after)

    global DEFAULT_DELETE_THRESHOLD
    DEFAULT_DELETE_THRESHOLD = int(args.delete_after)

# checks if user inserted details session
def is_default_session_details(session_name, session_description):
    if session_name == "Policy_clean_up_tool":
        if session_description == DATETIME_NOW_STR:
            return True
    return False

# Get global threshold
def get_global_thresholds():

    global DEFAULT_DISABLE_THRESHOLD
    global DEFAULT_DELETE_THRESHOLD

    global_thresholds = {}
    global_thresholds['disable'] = DEFAULT_DISABLE_THRESHOLD
    global_thresholds['delete'] = DEFAULT_DELETE_THRESHOLD


    return global_thresholds


# Get list of all the packages information that we should run on. If the user not specify package name - run over all existing packages
def packages_to_run(user_package, client):

    packages_to_run = []

    # If package-name isn't specified - run over all existing packages
    if user_package is None:

        # Note: api_query returns list of wanted objects received so far from the management server (in contrast to regular api_call that return only a limited number of objects)
        show_packages_res = client.api_query("show-packages", details_level="full")
        exit_failure("Failed to get all policies information.", show_packages_res)

        packages_to_run = show_packages_res.data.get('packages')

        # No packages at all
        if not packages_to_run:
            print_msg("There are no existing packages.")
            exit(0)

    else:
        show_package_res = client.api_call("show-package", {"name": user_package, "details-level": "full"})
        exit_failure("Failed to get policy {} information.".format(user_package), show_package_res)

        packages_to_run.append(show_package_res.data)

    return packages_to_run


# Get rule's thresholds.
# Disable and deleted thresholds are calculated by global thresholds or overrides thresholds (local override).
# Local thresholds- user can override the global thresholds by adding number to custom-fields per rule.
def get_rule_final_threshold(rule, field, threshold_type, global_thresholds):

    # Custom-field1 contains override for disable threshold
    local_threshold = rule.get('custom-fields', {}).get(field)
    # -1 represents a rule that should be skipped all time.
    if global_thresholds.get(threshold_type) == -1:
        return None
    # Empty value - use global threshold
    elif not local_threshold:
        return global_thresholds.get(threshold_type)
    # Don't touch override
    elif local_threshold == "-1":
        return None
    # Non-numeric value - skip rule
    elif local_threshold.isnumeric() is False:
        rule['skipped-reason'] = "{} threshold has non-numeric value".format(threshold_type)
        return None
    else:
        int_local_threshold = int(local_threshold)

        # Negative value - skip rule
        if int_local_threshold < 1:
            rule['skipped-reason'] = "{} threshold is a negative number".format(threshold_type)
            return None
        # Positive numeric value - use it as override
        else:
            return int_local_threshold


# Get rule last disabled time
def get_rule_disabled_time(rule):

    global DATETIME_FORMAT

    # Custum-field3 contains disabled time by the tool
    rule_disabled_time = rule.get('custom-fields', {}).get('field-3')

    # No disabled time, skip rule (no warning) - assume the rule didn't disable by the tool
    if not rule_disabled_time:
        return None

    # Convert last disabled-time to datetime object by DATETIME_FORMAT
    try:
      return datetime.datetime.strptime(rule_disabled_time, DATETIME_FORMAT)
    except (ValueError, TypeError):
      return None


# Update the valid targets structure for this policy - keep only valid targets
def update_package_valid_targets(package, valid_targets):

    package_name = package.get('name')
    package_valid_targets = valid_targets['packages-targets'].get(package_name)
    if not package_valid_targets:
        return

    installation_targets = package.get('installation-targets')

    # Package installation targets is all - only update all-targets-valid
    if installation_targets == 'all':
        package_valid_targets['all-targets-valid'] = valid_targets.get('all-targets-valid')

    # List of targets uid's, remove all targets that not in installation-targets & update all-targets-valid
    else:
        # Create set of installation-targets uids
        installation_targets_set = set([])
        for target in installation_targets:
            installation_targets_set.add(target.get('uid'))

            if target.get('uid') not in package_valid_targets['targets']:
                package_valid_targets['all-targets-valid'] = False

        # Remove all valid targets that not in installation targets
        for valid_target_uid in package_valid_targets['targets']:
            if valid_target_uid not in installation_targets_set:
                remove_target(valid_targets['packages-targets'], package, valid_target_uid)


# Get all gateway targets with hit count on & access-policy installed.
# Return dictionary from packages name to (dictionary of valid targets uid to valid targets)
def valid_packages_targets(packages, client):

    # Get all gateways & servers of current domain
    # Note: api_query returns list of wanted objects received so far from the management server (in contrast to regular api_call that return only a limited number of objects)
    show_gateways_servers_res = client.api_query("show-gateways-and-servers", details_level="full")
    exit_failure("Failed to get gateways & servers information.", show_gateways_servers_res)

    # Object to store all valid targets as dictionary from packages
    valid_targets = {}

    # True if all the package targets are valid
    valid_targets['all-targets-valid'] = True

    # Store dictionary from packages name to (dictionary of valid targets uid to valid targets)
    valid_targets['packages-targets'] = {}

    for object in show_gateways_servers_res.data:

        # Check if it is installable target
        if is_targetale_object(object) is True:

            if is_valid_package_target(packages, object, client) is True:
                add_valid_target(valid_targets['packages-targets'], object)
            else:
                valid_targets['all-targets-valid'] = False

    # If all domain targets invalid - exit
    if not valid_targets['packages-targets']:
        print_msg("All domain’s targets are invalid. " + REASON_OF_ALL_TARGETS_INVALID)

    # Foreach policy keep only the valid targets
    for package in packages:
        update_package_valid_targets(package, valid_targets)


    return valid_targets


# Check if a package target is valid
def is_valid_package_target(packages, target, client):

    # Set of packages names
    packages_names_dict = {}
    for package in packages:
        packages_names_dict[package.get('name')] = package

    policy_name = target.get('policy', {}).get('access-policy-name')

    return (policy_name in packages_names_dict) and is_access_policy_installed(target) and is_installation_updated(packages_names_dict[policy_name], target) and is_target_hitcount_on(target, client)


# Check if policy install
# s after modification
def is_installation_updated(package, target):

    policy_installation_time = convert_date_object_to_datetime(target.get('policy').get('access-policy-installation-date', {}))
    policy_last_modify_time = convert_date_object_to_datetime(package.get('meta-info', {}).get('last-modify-time', {}))

    # Install after modify
    return (policy_last_modify_time <= policy_installation_time)


# Add new valid target to the valid targets dictionary
def add_valid_target(packages_targets, valid_target):

    target_policy_name = valid_target['policy']['access-policy-name']

    target_policy = packages_targets.get(target_policy_name)

    if not target_policy:
        target_policy = {}
        # Flag that save if al the targets are valid
        target_policy['all-targets-valid'] = True
        # save the minimal installation time of the policy - to check if rule has modified in validate_rule
        target_policy['minimal-installation-time'] = convert_date_object_to_datetime(valid_target.get('policy').get('access-policy-installation-date', {}))
        target_policy['targets'] = {}
        packages_targets[target_policy_name] = target_policy

    target_policy['targets'][valid_target.get('uid')] = valid_target

    # Update minimal policy installation time
    target_installation_time = convert_date_object_to_datetime(valid_target.get('policy').get('access-policy-installation-date', {}))
    if target_installation_time < target_policy['minimal-installation-time']:
        target_policy['minimal-installation-time'] = target_installation_time


# Delete an existing target that became invalid from the valid targets dictionary
def remove_target(packages_targets, package, target_uid):

    package_name = package.get('name')
    package_valid_targets = packages_targets.get(package_name, None)

    # Remove target from policy valid targets
    if not package_valid_targets:
        package_valid_targets.pop(target_uid, None)

    # Remove package with no valid targets
    if not package_valid_targets:
        packages_targets.pop(package_name, None)


# Check if we can install policy on this object
def is_targetale_object(object):

    return object.get('network-security-blades', {}).get('firewall')


# Check if the target object contains access-policy
def is_access_policy_installed(target):

    return target.get('policy', {}).get('access-policy-installed')


# Check if the target hit count flag is on
def is_target_hitcount_on(target, client):

    # Get target information
    ##### These APIs provide direct access to different objects and fields in the database. As a result, when the objects schema change, scripts that relied on specific schema fields may break.#####
    ##### When you have the option, always prefer to use the documented APIs and not the generic APIs #####
    show_generic_object_res = client.api_call("show-generic-object", {"uid": target.get('uid'), "details-level": "full"})
    if is_failure("Failed to get {} target information".format(target.get('name')), show_generic_object_res):
        return False

    # Check if hit count flag in on
    if show_generic_object_res.data.get('firewallSetting', {}).get('hitCountFw1Enable') is False:
        return False

    return True


# Determine the packages the tool should run on (valid packages)
def validate_package(package, valid_targets):

    package_name = package.get('name')

    if package_name not in valid_targets['packages-targets']:
        package['skipped-reason'] = "All package targets are invalid. " + REASON_OF_ALL_TARGETS_INVALID
        return False

    return True


# Get res of show access-rulebase command with object-dictionary
def show_access_rulebase(layer, client):

    res_of_show_access_rulebase = api_call_command_with_objects_dictionary(client, "show-access-rulebase", details_level="standard",container_keys = ["rulebase"], payload={"uid": layer['uid'], "show-hits": "true", "hits-settings": {"from-date": "1970-01-02"}}) # for R80.10 we need to specify from date
    if skip_failure(layer, "Failed to get rulebase.", res_of_show_access_rulebase) is True:
        return None

    return res_of_show_access_rulebase

#It is recommended to use in api_query and not in api_call
#The use of the command 'api_call' in this function is because we want to get the data of rulebase and objects-dictionary at once.
def api_call_command_with_objects_dictionary(client, command, details_level="standard", container_keys=["objects"], payload=None):

    limit = 500  # each time get no more than 500 objects
    finished = False  # will become true after getting all the data
    all_objects = {}  # accumulate all the objects from all the API calls


    iterations = 0  # number of times we've made an API call
    if payload is None:
        payload = {}

    for key in container_keys:
        all_objects[key] = []

    # accumulate all the objects-dictionary from all the API calls
    all_objects["objects-dictionary"] = {}

    # are we done?
    while not finished:

        payload.update({"limit": limit, "offset": iterations * limit, "details-level": details_level})

        api_res = client.api_call(command, payload)

        if api_res.success is False:
            return api_res

        total_objects = api_res.data["total"]  # total number of objects
        received_objects = api_res.data["to"]  # number of objects we got so far
        for container_key in container_keys:
            all_objects[container_key] += api_res.data[container_key]

        all_objects["objects-dictionary"] = add_and_parse_object_dictionary_to_map(api_res.data["objects-dictionary"], all_objects["objects-dictionary"])

        # did we get all the objects that we're supposed to get
        if received_objects == total_objects:
            finished = True

        iterations += 1

    return all_objects

# Add only new object from object_dictionary that not exists in object_dictionary_as_map
def add_and_parse_object_dictionary_to_map(object_dictionary,object_dictionary_as_map):


    for object in object_dictionary:
        object_dictionary_as_map[object.get('uid')] = object

    return object_dictionary_as_map

# Get full rule-base as a list of rules
def get_rulebase(show_rulebase_res):

    rulebase = conceal_sections(show_rulebase_res.get('rulebase'))
    return rulebase


# Get object-dictionary from show access-rulebase as a map
def get_object_dictionary(show_rulebase_res):

    object_dictionary = show_rulebase_res.get('objects-dictionary')
    return object_dictionary

# Get rule last hit time
# Note: If the rule does not have any hits OR rule modified after the last hit, last hit time will be counted as the last modify time.
def get_rule_last_hit_time(rule):

    # Get last modify time & convert it to datetime object
    rule_last_modify_time = convert_date_object_to_datetime(rule['meta-info']['last-modify-time'])

    # Get last hit time & convert it to datetime object (if the rule has one hit - at least)
    if 'last-date' in rule['hits']:
        rule_last_hit_time = convert_date_object_to_datetime(rule['hits']['last-date'])
    else:
        return rule_last_modify_time

    if rule_last_hit_time > rule_last_modify_time:
        return rule_last_hit_time
    else:
        return rule_last_modify_time


# Read plan file as JSON format
def read_plan_json(file):

    try:
      with open(file, 'r') as import_plan_file:
        return json.load(import_plan_file)
    except Exception as e:
        print('Error: invalid json \'import-plan-file\'. %s' % e)
        exit(1)

# Write plan to log file in JSON format
def write_plan_json(plan, file):

    with open(file, 'w') as output_file:
        json.dump(plan, output_file, indent=4, default=jdefault, sort_keys=True)
        output_file.write('\n')


# Build the structure of the plan output - keep specific keys, add 'skipped', add summary
def build_output_structure(plan, summary, operation):

    new_plan = {}
    summary['total-candidate-disable-rules'] = 0
    summary['total-candidate-delete-rules'] = 0
    summary['total-skipped-packages'] = 0
    summary['total-skipped-layers'] = 0
    summary['total-skipped-rules'] = 0

    new_plan['operation'] = operation
    new_plan['thresholds'] = {"delete-after": get_global_thresholds().get("delete"), "disable-after": get_global_thresholds().get("disable")}
    new_plan['packages'] = []
    new_plan['skipped-packages'] = []

    # Keys to save
    keep_package_keys = ['uid', 'name', 'type']
    keep_skipped_package_keys = ['uid', 'name', 'type', 'skipped-reason']
    keep_layer_keys = ['uid', 'domain', 'name', 'shared', 'type', 'disable-rules', 'delete-rules', 'skipped-rules']
    keep_targets_keys = ['uid', 'name', 'type']

    for package in plan.get('packages', []):

        if 'skipped-reason' in package:
            new_package = {key: package.get(key, {}) for key in keep_skipped_package_keys}
            new_plan['skipped-packages'].append(new_package)
            summary['total-skipped-packages'] += 1
        else:
            new_package = {key: package.get(key, {}) for key in keep_package_keys}
            new_package['access-layers'] = []
            new_package['installation-targets'] = []

            for layer in package.get('access-layers', []):
                    new_layer = {key: layer.get(key, {}) for key in keep_layer_keys}

                    if 'skipped-reason' in layer:
                        new_package['skipped-layers'].append(new_layer)
                        summary['total-skipped-layers'] += 1
                    else:
                        new_layer['disable-rules'] = {'total': len(layer.get('disable-rules', [])), "rules": layer.get('disable-rules', [])}
                        new_layer['delete-rules'] = {'total': len(layer.get('delete-rules', [])), "rules": layer.get('delete-rules', [])}
                        new_layer['skipped-rules'] = {'total': len(layer.get('skipped-rules', [])), "rules": layer.get('skipped-rules', [])}
                        new_layer['objects-dictionary'] = layer.get('objects-dictionary', [])
                        new_package['access-layers'].append(new_layer)

                        summary['total-candidate-disable-rules'] += len(layer.get('disable-rules', []))
                        summary['total-candidate-delete-rules'] += len(layer.get('delete-rules', []))
                        summary['total-skipped-rules'] += len(layer.get('skipped-rules', []))

            installation_targets = package.get('installation-targets')
            if installation_targets == 'all':
                new_package['installation-targets'].append(installation_targets)
            else:
                for target in package.get('installation-targets', []):
                    new_target = {key: target.get(key, {}) for key in keep_targets_keys}
                    new_package['installation-targets'].append(new_target)

            new_plan['packages'].append(new_package)

    return new_plan


# Print the summary we built to the user
def print_summary(summary):

    print_msg("Plan Summary:")
    print_msg("Thresholds: {{delete-after: {0} days, disable-after: {1} days}}".format(get_global_thresholds().get("delete"), get_global_thresholds().get("disable")))
    print_msg("  {0} {1} candidate to be disabled.".format(summary.get('total-candidate-disable-rules'), get_appropriate_wording_by_total_number(summary.get('total-candidate-disable-rules'), "rule", True)))
    print_msg("  {0} {1} candidate to be deleted.".format(summary.get('total-candidate-delete-rules'), get_appropriate_wording_by_total_number(summary.get('total-candidate-delete-rules'), "rule", True)))
    print_msg("  {0} {1} skipped. See skipped-packages & skipped-reason in json output file.".format(summary.get('total-skipped-packages'), get_appropriate_wording_by_total_number(summary.get('total-skipped-packages'), "package", False)))
    print_msg("  {0} {1} skipped. See skipped-layers & skipped-reason in json output file.".format(summary.get('total-skipped-layers'), get_appropriate_wording_by_total_number(summary.get('total-skipped-layers'), "layer", False)))
    print_msg("  {0} {1} skipped. See skipped-rules & skipped-reason in json output file.".format(summary.get('total-skipped-rules'), get_appropriate_wording_by_total_number(summary.get('total-skipped-rules'), "rule", False)))

def get_appropriate_wording_by_total_number(total_num, word_to_change, is_present):
    if total_num == 1:
        if is_present is True:
            word_to_change += " is"
        else:
            word_to_change += " was"
    else:
        if is_present is True:
            word_to_change += "s are"
        else:
            word_to_change += "s were"

    return word_to_change

# Conceal all sections from rulebase - make same
# rulebase without sections
def conceal_sections(rulebase):

    new_rulebase = []

    for rule in rulebase:
        # Rulebase has section
        if 'rulebase' in rule:
            new_rulebase.extend(rule.get('rulebase'))
        else:
            new_rulebase.append(rule)

    return new_rulebase


# Apply the plan results
def apply_plan(client, plan):

    for package in get_value_by_key_with_validation(plan, 'packages'):
        print_msg("Package {}".format(package['name']))

        for layer in get_value_by_key_with_validation(package, 'access-layers'):

            print_msg("  Layer {}".format(layer['name']))

            for rule in get_value_by_key_with_validation(get_value_by_key_with_validation(layer, 'disable-rules'), 'rules'):
                if disable_rule(rule, layer, client) is False:
                    return False

            for rule in get_value_by_key_with_validation(get_value_by_key_with_validation(layer, 'delete-rules'), 'rules'):
                if delete_rule(rule, layer, client) is False:
                    return False
    return True

# get value by key from object with validation
def get_value_by_key_with_validation(object, key):

    res_data = object.get(key)
    if res_data is None:
       print('\n Error: \'import-plan-file\' is corrupted, missing \'{}\' object'.format(key))
       exit(1)

    return res_data

# Login with user arguments - in non-apply operations, login with read-only
def login(user_args, client):

    # Read-only login in non-apply operations
    login_read_only = (not is_apply_operation(user_args.operation))
    session_details = get_session_details(user_args, login_read_only)
    if user_args.root is not None and user_args.root.lower() == 'true':
        if user_args.management == '127.0.0.1':
            login_res = client.login_as_root(domain=user_args.domain, payload=dict({"read-only": str(login_read_only)}, **session_details))
        else:
            print_msg(" Error: Command contains ambigious parameters. Management server remote ip is unexpected when logging in as root.")
            exit(1)
    else:
        login_res = client.login(user_args.username, user_args.password, domain=user_args.domain, read_only=login_read_only, payload=session_details)

    exit_failure("Failed to login.", login_res)


def get_session_details(user_args, login_read_only):

    session_details = {}
    if login_read_only is False:
            session_details["session-name"] = user_args.session_name
            session_details["session-description"] = user_args.session_description

    return session_details


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

# delete the rule
def delete_rule(rule, layer, api_client):

    delete_rule_res = api_client.api_call("delete-access-rule", {"uid": rule['uid'], "layer": layer['uid']})
    return not is_failure("    Failed to delete rule No.{} with UID {}.".format(rule['rule-number'], rule['uid']), delete_rule_res)


# Determine which layers should be skipped
def validate_layer(layer):

    if is_global_object(layer) is True:
        return False

    return True


# Check if the install-on list contains invalid target & rule is updated on targets
def validate_rule(rule, package, valid_targets):

    global INSTALL_ON_ALL_TARGETS

    package_name = package.get('name')
    install_on = rule.get('install-on')
    package_valid_targets = valid_targets['packages-targets'].get(package_name)

    # Validate that rule is up-do-date
    rule_last_modify_time = convert_date_object_to_datetime(rule['meta-info']['last-modify-time'])
    package_installation_time = package_valid_targets['minimal-installation-time']
    if rule_last_modify_time > package_installation_time:
        rule['skipped-reason'] = "has modified after policy installation"
        return False

    # Installation targets all - constant UID
    if install_on[0] == INSTALL_ON_ALL_TARGETS:
        if package_valid_targets.get('all-targets-valid') is True:
            return True
        else:
            rule['skipped-reason'] = "one of the targets in the install-on list is invalid"
            return False

    valid_targets = package_valid_targets.get('targets', {})

    for target_uid in install_on:
        if target_uid not in valid_targets:
            rule['skipped-reason'] = "target with UID {} in the install-on list is invalid".format(target_uid)
            return False

    return True


# Check if domain hit count global property flag is on. If the flag is off - exit
def mgmt_hitcount_on(client, domain):

    # Get global properties
    ##### These APIs provide direct access to different objects and fields in the database. As a result, when the objects schema change, scripts that relied on specific schema fields may break.#####
    ##### When you have the option, always prefer to use the documented APIs and not the generic APIs #####
    show_prop_res = client.api_call("show-generic-objects", {"class-name": "com.checkpoint.objects.classes.dummy.CpmiFirewallProperties", "details-level": "full"})
    exit_failure("Failed to get properties.", show_prop_res)

    domain_name = domain.get('name')

    # Loop over all global properties, and search for current domain hit count flag
    for obj in show_prop_res.data.get('objects'):
        if (obj['domain']['name'] == domain_name):
            if obj.get('enableHitCount') == 0:
                print_msg("Hit Count flag is off for domain {}, please turn it on.".format(domain['name']))
                exit(0)
            else:
                return True


#get list of all objects from objects dictionary that appear in rule only by uid
def get_objects_of_rule_from_objects_dictionary(rule, object_dictionary):

    #accumulate all the objects rule from objects-dictionary that appear by uid
    objects_of_rule_to_add = []

    for value in rule.values():
        if(isinstance(value, (list,dict))):
          for uid in value:
            specific_object_to_add = object_dictionary.get(uid)
            if(specific_object_to_add is not None):
              objects_of_rule_to_add.append(specific_object_to_add)

        else:
             specific_object_to_add = object_dictionary.get(value)
             if (specific_object_to_add is not None):
                 objects_of_rule_to_add.append(specific_object_to_add)

    return objects_of_rule_to_add


#updates and return the sub dictionary with objects of rule that didn't exist before
def add_to_sub_dictionary(objects_of_rule_to_add, sub_dictionary):

    for current_object in objects_of_rule_to_add:
        sub_dictionary[current_object.get('uid')] = current_object

    return sub_dictionary

#parse map of sub objects dictionary to list of values
def parse_sub_objects_dictionary_map_to_list_of_value(sub_dictionary):

    list_values_of_sub_objects_dictionary = []

    for value in sub_dictionary.values():
        list_values_of_sub_objects_dictionary.append(value)

    return list_values_of_sub_objects_dictionary


# Determine in which conditions the rule should be disabled
# Function checks if rule should be disable based on hit count. Rule would be disabled if it's last hit date or last modified date (The closest date) is former to today's date minus the threshold.
# Note: This function can be adjust according to needs. If you want to change the logic which determines whether rule should be disabled not based on hit count.
def rule_should_be_disabled(rule, global_thresholds):

    global DATETIME_NOW

    # Calculate final thresholds
    final_disable_threshold = get_rule_final_threshold(rule, 'field-1', 'disable', global_thresholds)
    if final_disable_threshold is None:
        return False

    # Get rule last hit time
    rule_last_hit_time = get_rule_last_hit_time(rule)

    # Disable rule - no hits too long
    if rule_last_hit_time + datetime.timedelta(days=final_disable_threshold) < DATETIME_NOW:
        return True

    return False

# Determine in which conditions the rule should be deleted
def rule_should_be_deleted(rule, global_thresholds):

    # Get final delete threshold (after local overrides)
    final_delete_threshold = get_rule_final_threshold(rule, 'field-2', 'delete', global_thresholds)
    if final_delete_threshold is None:
        return False

    # Get rule disabled time by the tool
    rule_disabled_time = get_rule_disabled_time(rule)
    if rule_disabled_time is None:
        return False

    # Delete rule - disabled too long
    if rule_disabled_time + datetime.timedelta(days=final_delete_threshold) < DATETIME_NOW:
        return True

    return False


# Convert checkpoint date reply to datetime object
def convert_date_object_to_datetime(date_object):

    date_posix = date_object.get('posix', 0)
    # milli-seconds to seconds
    date_posix = int(date_posix)/1000
    return datetime.datetime.fromtimestamp(date_posix)


# Check if the object is global object
def is_global_object(object):

    global GLOBAL_DOMAIN_NAME

    return (object['domain']['name'] == GLOBAL_DOMAIN_NAME)


# Determine in which operations the tool should create plan
def is_plan(args):

    return (args.import_plan_file is None)


# Determine in which operations the tool should disable/delete rules (apply, apply_without_publish)
def is_apply_operation(operation):

    return (operation == "apply") or (operation == "apply_without_publish")


# Determine in which operations the tool should publish changes (apply)
def is_publish_operation(operation):

    return (operation == "apply")


# Check if the API-call failed & skipped reason message
def skip_failure(skipped_object, error_msg, response):

    if (hasattr(response, 'success')):
        if response.success is False:
            skipped_object['skipped-reason'] = error_msg + " Error: {}".format(response.error_message.encode('utf-8'))
            return True

    return False


# Check if the API-call failed & print error message
def is_failure(error_msg, response):

    if response.success is False:
        print_msg(error_msg + " Error: {}".format(response.error_message.encode('utf-8')))
        return True

    return False

# Check if running on MDS and didn't supply domain
def check_validation_for_mds(client, domain):

    api_res = client.api_call("show-mdss")
    if int(api_res.data.get('total')) != 0:
        if domain is None:
            print_msg(" Error: You must provide a domain in a Multi-Domain-Management environment.")
            exit(1)


# Exit if the API-call failed & print error message
def exit_failure(error_msg, response):

    if response.success is False:
        print_msg(error_msg + " Error: {}".format(response.error_message))
        exit(1)


# Print message with time description
def print_msg(msg):
    print("[{}] {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))


# Default value for non-json serializable objects
def jdefault(obj):
    return "<not JSON serializable>"


def main():

    global DATETIME_NOW

    print()

    # Store output file information, will be serialize to JSON file
    plan = {}

    # Parse user arguments
    user_args = parse_arguments()

    client_args = APIClientArgs(server=user_args.management, port=user_args.port)

    with APIClient(client_args) as client:

        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print_msg("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # Login to server, (read-only in non-apply operations)
        login(user_args, client)

        # Get global thresholds (disable & delete)
        global_thresholds = get_global_thresholds()

        # Check if running on MDS and didn't supply domain
        check_validation_for_mds(client, user_args.domain)

        # Plan
        if is_plan(user_args):

            print_msg("Plan")

            # Store list of all packages information that we should run on
            plan['packages'] = packages_to_run(user_args.package, client)

            # If management hit count flag in off, hits won't be counted - exit
            mgmt_hitcount_on(client, plan['packages'][0]["domain"])

            # Pre-processing to calculate all invalid targets
            print_msg("Validate targets")
            valid_targets = valid_packages_targets(plan['packages'], client)

            for package in plan.get('packages'):
                # Skip invalid packages (all installation targets are invalid)
                if validate_package(package, valid_targets) is False:
                    continue

                print_msg("Package {}".format(package['name']))

                # Loop over policy layers
                for layer in package.get('access-layers'):

                    print_msg("  Layer {}".format(layer['name']))

                    # Skip invalid layers (global layers)
                    if validate_layer(layer) is False:
                        continue

                    layer['skipped-rules'] = []
                    layer['disable-rules'] = []
                    layer['delete-rules'] = []
                    sub_dictionary = {}

                    show_access_rulebase_res = show_access_rulebase(layer, client)
                    object_dictionary_as_map = get_object_dictionary(show_access_rulebase_res)

                    # Get full rule-base as a list of rules
                    rulebase = get_rulebase(show_access_rulebase_res)
                    if rulebase is None:
                        continue

                    # Loop over layer rules
                    for rule in rulebase:

                        # Rule is enabled
                        if rule.get('enabled') is True:

                            # Skip rule with invalid target in install-on list OR rule modify after installation
                            if validate_rule(rule, package, valid_targets) is False:
                                if 'skipped-reason' in rule:
                                    layer['skipped-rules'].append(rule)
                                continue

                            # Check if rule should be disabled - no hits for too long
                            if rule_should_be_disabled(rule, global_thresholds) is True:

                                objects_of_rule_to_add = get_objects_of_rule_from_objects_dictionary(rule, object_dictionary_as_map)
                                sub_dictionary = add_to_sub_dictionary(objects_of_rule_to_add, sub_dictionary)

                                # Add to plan that the rule should be disabled
                                layer['disable-rules'].append(rule)

                        # Rule is disabled
                        else:
                            # check if the rule should be deleted - disabled too long
                            if rule_should_be_deleted(rule, global_thresholds) is True:
                                objects_of_rule_to_add = get_objects_of_rule_from_objects_dictionary(rule, object_dictionary_as_map)
                                sub_dictionary = add_to_sub_dictionary(objects_of_rule_to_add, sub_dictionary)

                                # Add to plan that the rule should be deleted
                                layer['delete-rules'].append(rule)

                    layer['objects-dictionary'] = parse_sub_objects_dictionary_map_to_list_of_value(sub_dictionary)

            summary = {};
            plan = build_output_structure(plan, summary, user_args.operation)

            if valid_targets['packages-targets']:
                print_summary(summary)

            # Write plan to log file in JSON format
            write_plan_json(plan, user_args.output_file)

            print_msg('Plan process has finished.\n')
            print_msg('The output file in: {}'.format(os.path.abspath(user_args.output_file)))

        # Get plan-file path as argument
        else:
            plan = read_plan_json(user_args.import_plan_file)


        # Apply plan only when the operation is apply/apply_without_publish
        if is_apply_operation(user_args.operation) is True:

            print()
            print_msg("Apply plan")

            # Disable & Delete rules by the plan. If apply failed in one of them - stop and discard changes
            if apply_plan(client, plan) is False:

                print_msg("Discard")
                discard_res = client.api_call("discard")
                is_failure("Failed to discard changes.", discard_res)
                print()
                exit(1)

            # Publish changes only when the operation is apply
            if is_publish_operation(user_args.operation):

                print_msg("Publish")
                publish_res = client.api_call("publish")
                is_failure("Failed to publish changes.", publish_res)

            else:

                print_msg("Continue session in smartconsole")
                continue_smartconsole_res = client.api_call("continue-session-in-smartconsole")
                is_failure("Failed to continue session in smartconsole.", continue_smartconsole_res)

            print_msg('Apply process has finished successfully.')

        print()

if __name__ == "__main__":
    main()
