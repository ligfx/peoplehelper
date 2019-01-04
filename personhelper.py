#!/usr/bin/env python
# codec: utf-8

import sys

if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

import csv
import tempfile
import re
import os
import traceback
import shutil
import io
import collections
import urllib.parse
import googleapiclient.discovery
import httplib2
import itertools
import oauth2client.file, oauth2client.client, oauth2client.tools
import requests
import simple_salesforce
import salesforcecookies
import inspect
import shlex
import subprocess

if hasattr(sys, "frozen") and sys.frozen == "macosx_app":
    import macos_gui_backend

    BACKEND = macos_gui_backend

    # keyring (used by salesforcecookies) breaks under py2app unless we do this explicitly
    import keyring
    import keyring.backends.OS_X

    keyring.set_keyring(keyring.backends.OS_X.Keyring())
else:
    import terminal_backend

    BACKEND = terminal_backend


def myexit(retcode=0):
    print("Exiting (most recent call last):")
    for f in inspect.stack()[1:]:
        info = inspect.getframeinfo(f[0])
        print(
            '  File "%s", line %s, in %s' % (info.filename, info.lineno, info.function)
        )
        for line in info.code_context:
            print("    %s" % line.strip())
    sys.exit(retcode)


def get_anymailfinder_api_key():
    anymailfinder_api_path = os.path.expanduser(
        "~/Library/Application Support/com.pubnub.emailfinder/anymailfinder_api_key.txt"
    )
    try:
        with open(anymailfinder_api_path) as f:
            return f.read().strip()
    except FileNotFoundError:
        pass
    try:
        os.makedirs(os.path.dirname(anymailfinder_api_path))
    except FileExistsError:
        pass
    key = BACKEND.question("Please enter Anymailfinder.com API key:")
    with open(anymailfinder_api_path, "w") as f:
        f.write(key)
    return key


def get_hunter_api_key():
    hunter_api_path = os.path.expanduser(
        "~/Library/Application Support/com.pubnub.emailfinder/hunter_api_key.txt"
    )
    try:
        with open(hunter_api_path) as f:
            return f.read().strip()
    except FileNotFoundError:
        pass
    try:
        os.makedirs(os.path.dirname(hunter_api_path))
    except FileExistsError:
        pass
    key = BACKEND.question("Please enter Hunter.io API key:")
    with open(hunter_api_path, "w") as f:
        f.write(key)
    return key


def get_google_credentials():
    credentials_path = os.path.expanduser(
        "~/Library/Application Support/com.pubnub.emailfinder/google_sheets_credentials.json"
    )
    if not os.path.exists(credentials_path):
        try:
            os.makedirs(os.path.dirname(credentials_path))
        except FileExistsError:
            pass
        while True:
            BACKEND.error(
                "Need to create %s.\n\nFollow instructions at: https://developers.google.com/sheets/api/quickstart/python"
                % credentials_path
            )
            if os.path.exists(credentials_path):
                break
            if os.path.exists(os.path.expanduser("~/Downloads/credentials.json")):
                shutil.copyfile(
                    os.path.expanduser("~/Downloads/credentials.json"), credentials_path
                )
                break

    token_path = os.path.expanduser(
        "~/Library/Caches/com.pubnub.emailfinder/token.json"
    )
    if not os.path.exists(token_path):
        try:
            os.makedirs(os.path.dirname(token_path))
        except FileExistsError:
            pass

    store = oauth2client.file.Storage(token_path)
    creds = store.get()
    if not creds or creds.invalid:
        flow = oauth2client.client.flow_from_clientsecrets(
            credentials_path, SCOPES, redirect_uri="urn:ietf:wg:oauth:2.0:oob"
        )
        print(flow)
        auth_uri = flow.step1_get_authorize_url()
        subprocess.run(["open", auth_uri])
        code = BACKEND.question(
            "Please follow the authorization flow in your web browser, then enter the code:"
        )
        while True:
            try:
                creds = flow.step2_exchange(code)
                break
            except oauth2client.client.FlowExchangeError:
                pass
            code = BACKEND.question(
                "Incorrect code! Please follow the authorization flow in your web browser, then enter the code:"
            )
        store.put(creds)
        BACKEND.notification(
            "You can now close the authorization flow in your web browser."
        )

    return creds


def parse_google_sheets_url(service, url):
    m = re.fullmatch(
        r"https://docs\.google\.com/spreadsheets/d/([^/]+).*#gid=(\d+)", url
    )
    if not m:
        BACKEND.error(
            "URL should look something like https://docs.google.com/spreadsheets/d/1GlFX3/edit#gid=234"
        )
        myexit()
    spreadsheet_id = m.groups()[0]
    sheet_gid = m.groups()[1]

    sheets = (
        service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()["sheets"]
    )
    for x in sheets:
        if str(x["properties"]["sheetId"]) == sheet_gid:
            range_name = x["properties"]["title"]
            break

    return (spreadsheet_id, sheet_gid, range_name)


def get_google_sheets_values(service, url):
    spreadsheet_id, sheet_gid, range_name = parse_google_sheets_url(service, url)
    result = (
        service.spreadsheets()
        .values()
        .get(
            spreadsheetId=spreadsheet_id, range=range_name, valueRenderOption="FORMULA"
        )
        .execute()
    )
    return result.get("values", [])


def update_google_sheets_values(service, url, values):
    spreadsheet_id, sheet_gid, range_name = parse_google_sheets_url(service, url)
    result = (
        service.spreadsheets()
        .values()
        .update(
            spreadsheetId=spreadsheet_id,
            range=range_name,
            valueInputOption="USER_ENTERED",
            body={"values": values},
        )
        .execute()
    )
    print(result)


def find_matching(regex, seq, default=None):
    matching = [item for item in seq if re.fullmatch(regex, item, flags=re.IGNORECASE)]
    if len(matching) > 1:
        raise Exception("Too many items matching '%s' in: %s" % (regex, seq))
    if len(matching) == 0:
        if default:
            seq.append(default)
            return default
        raise Exception("No items matching '%s' in: %s" % (regex, seq))
    return matching[0]


def escape_soql(obj):
    if isinstance(obj, str):
        return "'%s'" % obj.replace("'", "\\'")
    elif isinstance(obj, int):
        return str(obj)
    else:
        raise NotImplementedError(obj)


def find_salesforce_emails_for_ids(sf, ids):
    ids = list(ids)
    if not ids:
        return []

    # TODO: sanitize input

    result = sf.query(
        "select Email, Id from Lead where IsDeleted = False and IsConverted = False and ("
        + " or ".join("id = %s" % escape_soql(id) for id in ids)
        + ")"
    )
    assert result["done"]
    leads = [(x["Email"], x["Id"]) for x in result["records"]]

    result = sf.query(
        "select Email, Id from Contact where IsDeleted = False and ("
        + " or ".join("id = %s" % escape_soql(id) for id in ids)
        + ")"
    )
    assert result["done"]
    contacts = [(x["Email"], x["Id"]) for x in result["records"]]

    return leads + contacts


def find_salesforce_ids_and_emails_for_first_names_last_names_and_domains(sf, seq):
    seq = list(seq)
    if not seq:
        return []

    # TODO: better matching of domains to accounts?

    result = sf.query(
        """
    select
      Id,
      Email,
      FirstName,
      LastName
    from Lead
    where
      IsDeleted = False
      and IsConverted = False
      and (
  """
        + " or ".join(
            "(FirstName = %s and LastName = %s and Email like %s)"
            % (escape_soql(x[0]), escape_soql(x[1]), escape_soql("%" + x[2]))
            for x in seq
        )
        + ")"
    )
    assert result["done"]
    leads = [
        (x["Id"], x["Email"], x["FirstName"], x["LastName"]) for x in result["records"]
    ]

    result = sf.query(
        """
    select
      Id,
      Email,
      FirstName,
      LastName
    from Contact
    where
      IsDeleted = False
      and (
  """
        + " or ".join(
            "(FirstName = %s and LastName = %s and Email like %s)"
            % (escape_soql(x[0]), escape_soql(x[1]), escape_soql("%" + x[2]))
            for x in seq
        )
        + ")"
    )
    assert result["done"]
    contacts = [
        (x["Id"], x["Email"], x["FirstName"], x["LastName"]) for x in result["records"]
    ]

    return leads + contacts


def find_salesforce_ids_for_emails(sf, emails):
    emails = list(emails)
    if not emails:
        return []

    result = sf.query(
        "select Id, Email from Lead where IsDeleted = False and IsConverted = False and ("
        + " or ".join("Email = %s" % escape_soql(email) for email in emails)
        + ")"
    )
    assert result["done"]
    leads = [(x["Id"], x["Email"]) for x in result["records"]]

    result = sf.query(
        "select Id, Email from Contact where IsDeleted = False and ("
        + " or ".join("Email = %s" % escape_soql(email) for email in emails)
        + ")"
    )
    assert result["done"]
    contacts = [(x["Id"], x["Email"]) for x in result["records"]]

    return leads + contacts


try:
    SCOPES = "https://www.googleapis.com/auth/spreadsheets"
    ANYMAILFINDER_API_KEY = get_anymailfinder_api_key()
    HUNTER_API_KEY = get_hunter_api_key()

    GOOGLE_SHEETS_SERVICE = googleapiclient.discovery.build(
        "sheets", "v4", http=get_google_credentials().authorize(httplib2.Http())
    )

    if len(sys.argv) == 1:
        url = BACKEND.question("Google Sheets URL:")
    elif len(sys.argv) == 2:
        url = sys.argv[1]
    else:
        BACKEND.error("Bad arguments: %s" % sys.argv)
        myexit(0)

    print("Downloading data from Google Sheets...")
    values = get_google_sheets_values(GOOGLE_SHEETS_SERVICE, url)
    colnames = values[0]
    data = []
    for row in values[1:]:
        data.append(
            collections.OrderedDict(itertools.zip_longest(colnames, row, fillvalue=""))
        )

    name_colname = find_matching(r"name", colnames)
    domain_colname = find_matching(r"(company[\s_]*)?(domain|website|url)", colnames)
    email_colname = find_matching(r"email", colnames, "email")
    company_colname = find_matching(r"company([\s_]*name)?", colnames, "company")
    salesforce_id_colname = find_matching(
        r"((salesforce|sfdc)[\s_]*)?(contact[\s_*])?id", colnames, "salesforce_id"
    )
    title_colname = find_matching(r"title", colnames, "title")
    anymailfinder_status_colname = find_matching(
        r"anymailfinder[\s_]*status", colnames, "anymailfinder_status"
    )
    hunterio_status_colname = find_matching(
        r"hunterio[\s_]*status", colnames, "hunterio_status"
    )

    instance_url, session_id = salesforcecookies.get_instance_url_and_session()
    sf = simple_salesforce.Salesforce(instance_url=instance_url, session_id=session_id)

    # checks
    viable_data = []
    for item in data:
        for key in colnames:
            item[key] = str(item.get(key, "")).strip()

    # if salesforce ID but no email, pull email from salesforce
    # this can happen if e.g. you pick a duplicate manually
    print("Populating email addresses from SFDC IDs...")
    working_set = [
        item for item in data if item[salesforce_id_colname] and not item[email_colname]
    ]
    result = find_salesforce_emails_for_ids(
        sf, [item[salesforce_id_colname] for item in working_set]
    )
    for item in working_set:
        matches = [r for r in result if r[1] == item[salesforce_id_colname]]
        if len(matches) > 1:
            raise Exception("Too many objects matching: %s" % matches)
        if len(matches) == 1:
            item[email_colname] = matches[0][0]
            print(
                "Found Email for %s for SFDC ID %s: %s"
                % (item[name_colname], item[salesforce_id_colname], item[email_colname])
            )

    # get domain from email address
    print("Populating domain from existing email addresses...")
    for item in data:
        if item[domain_colname] or not item[email_colname]:
            continue
        item[domain_colname] = item[email_colname].split("@")[1]

    # clean up domain
    print("Cleaning up domains...")
    for item in data:
        if not item[domain_colname]:
            continue
        netloc = (
            urllib.parse.urlparse(item[domain_colname]).netloc or item[domain_colname]
        )
        if netloc.startswith("www."):
            netloc = netloc[4:]
        netloc = netloc.lower()
        if netloc:
            item[domain_colname] = netloc

    # check salesforce for matching name and email domain
    print("Searching SFDC for matching leads/contacts...")
    working_set = [
        item
        for item in data
        if not item[email_colname]
        and not item[salesforce_id_colname]
        and item[name_colname]
        and item[domain_colname]
    ]
    result = find_salesforce_ids_and_emails_for_first_names_last_names_and_domains(
        sf,
        [
            (
                item[name_colname].split(" ")[0],
                item[name_colname].split(" ")[-1],
                item[domain_colname],
            )
            for item in working_set
        ],
    )
    for item in working_set:
        matches = [
            r
            for r in result
            if r[1].split("@", 1)[-1] == item[domain_colname]
            and r[2] == item[name_colname].split(" ")[0]
            and r[3] == item[name_colname].split(" ")[-1]
        ]
        if len(matches) > 1:
            raise Exception("Too many objects matching: %s" % matches)
        if len(matches) == 1:
            item[salesforce_id_colname] = matches[0][0]
            item[email_colname] = matches[0][1]
            # item[email_source_colname] = 'salesforce'
            print(
                "Found SFDC ID and Email for %s: %s %s"
                % (item[name_colname], item[salesforce_id_colname], item[email_colname])
            )

    # check anymailfinder
    print("Searching for emails with Anymail Finder...")
    for item in data:
        if (
            item[email_colname]
            or item[anymailfinder_status_colname]
            or not item[name_colname]
            or not item[domain_colname]
        ):
            continue

        try:
            resp = requests.post(
                "https://api.anymailfinder.com/v4.0/search/person.json",
                headers={"X-API-Key": ANYMAILFINDER_API_KEY},
                json={"full_name": item[name_colname], "domain": item[domain_colname]},
            )

            if resp.status_code == 200:
                # success
                item[email_colname] = resp.json()["email"]
                item[anymailfinder_status_colname] = resp.text
                # item[email_source_colname] = 'anymailfinder'
                # item[email_class_colname] = resp.json()['email_class']
                # item[email_alternatives_colname] = resp.json()['alternatives']
                print(
                    "Found email for %s from Anymailfinder: %s"
                    % (item[name_colname], item[email_colname])
                )
            # elif resp.status_code in (404, 451):
            #   print("Not in Anymailfinder")
            #   item[anymailfinder_status_colname] = "404 " + resp.text
            #   pass
            else:
                item[anymailfinder_status_colname] = (
                    str(resp.status_code) + " " + resp.text
                )
        except Exception as e:
            item[anymailfinder_status_colname] = str(e)

    # check hunterio
    print("Searching for emails with Hunter.io...")
    for item in data:
        if (
            item[email_colname]
            or item[hunterio_status_colname]
            or not item[name_colname]
            or not item[domain_colname]
        ):
            continue

        resp = requests.get(
            "https://api.hunter.io/v2/email-finder",
            params={
                "domain": item[domain_colname],
                "api_key": HUNTER_API_KEY,
                "first_name": item[name_colname].split(" ")[0],
                "last_name": item[name_colname].split(" ")[-1],
            },
        )
        if resp.status_code == 200:
            item[email_colname] = resp.json()["data"]["email"]
            item[hunterio_status_colname] = resp.text
            print(
                "Found email for %s from Hunter.io: %s"
                % (item[name_colname], item[email_colname])
            )
        else:
            item[hunterio_status_colname] = str(resp.status_code) + " " + resp.text

    # check salesforce for objects with matching email
    print("Checking email addresses against existing SFDC leads/contacts...")
    working_set = [item for item in data if item[email_colname]]
    result = find_salesforce_ids_for_emails(
        sf, [item[email_colname] for item in working_set]
    )
    for item in working_set:
        # TODO: what if the matching name or title is different?
        matches = [r for r in result if r[1].lower() == item[email_colname].lower()]
        if len(matches) > 1 and item[salesforce_id_colname]:
            pass
        elif len(matches) > 1:
            raise Exception("Too many objects matching: %s" % matches)
        elif len(matches) == 1:
            old_salesforce_id = item[salesforce_id_colname]
            item[salesforce_id_colname] = matches[0][0]
            if old_salesforce_id != item[salesforce_id_colname]:
                print(
                    "Mapped %s <%s> to Salesforce '%s' (previously '%s')"
                    % (
                        item[name_colname],
                        item[email_colname],
                        item[salesforce_id_colname],
                        old_salesforce_id,
                    )
                )
        elif item[salesforce_id_colname]:
            print(
                "WARNING: Email '%s' is mapped to '%s' locally, but doesn't exist in SFDC (%s)"
                % (item[email_colname], item[salesforce_id_colname], matches)
            )

    # add new ones to salesforce
    print("Adding new prospects to SFDC...")
    for item in data:
        if (
            item[salesforce_id_colname]
            or not item[email_colname]
            or not item[name_colname]
        ):
            continue

        salesforce_lead = {
            "FirstName": item[name_colname].split(" ")[0],
            "LastName": item[name_colname].split(" ", 1)[1],
            "Email": item[email_colname],
            "Company": item[company_colname] or item[email_colname],
            "Title": item[title_colname],
        }
        result = sf.Lead.create(salesforce_lead)
        if result["success"]:
            item[salesforce_id_colname] = result["id"]
            print(
                "Created object in Salesforce for %s: %s"
                % (item[email_colname], item[salesforce_id_colname])
            )
        else:
            print("ERROR creating %s:" % item[email_colname], result["errors"])
        # print(result)

    # TODO: only write out if something changed
    # TODO: handle errors better
    print("Uploading data to Google Sheets...")
    new_data = [colnames]
    for item in data:
        row = []
        for colname in colnames:
            value = item[colname] or ""
            if value.startswith("+"):
                value = "'" + value
            row.append(value)
        new_data.append(row)

    update_google_sheets_values(GOOGLE_SHEETS_SERVICE, url, new_data)
    BACKEND.notification("Done!")

except Exception as e:
    print(traceback.format_exc())
    BACKEND.error(type(e).__name__ + ": " + str(e) + "\n\n" + traceback.format_exc())
