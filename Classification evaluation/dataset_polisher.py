import os
import csv
import re
from datetime import datetime

import pandas
import pandas as pd

import preprocessor
from url_enricher import get_fullhostname, get_dns_info

from dotenv import load_dotenv


# Function to convert date string to datetime object
def convert_to_datetime(date_str):
    # dates have the following format: Fri, 29 Jun 2001 08:36:09 -0500
    if date_str and isinstance(date_str, str):
        date_str = re.sub(r'\s*[-+][0-9]*\s*', '', date_str)  # remove any +0100 from the string
        date_str = re.sub(r'^.*,\s*', '', date_str)  # remove the day of the week from the start of the string
        date_str = re.sub(r'\s*\([^)]*\)$', '', date_str)  # remove any (CEST) or similar from the end of the string
        date_str = re.sub(r'\s*[a-zA-Z]*\s*$', '', date_str)  # remove any GMT or similar from the end of the string
        formats_to_try = [
            "%d %b %Y %H:%M:%S",
            "%d %b %Y %H:%M:%S %z",
            "%-d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %z"
        ]
        for format_str in formats_to_try:
            try:
                date = datetime.strptime(date_str, format_str)
                # Check if the date is valid and less than 2023
                if date < datetime(2023, 1, 1, tzinfo=date.tzinfo):
                    return date
            except ValueError:
                continue
        # print("Can't convert " + date_str + " into a valid date")
    return None


def get_preprocessed_dataset(dataset_name):
    df = pd.read_csv(os.path.join(base_path, dataset_name))

    df["headers"] = ""  # add empty column
    df["urls"] = ""  # add empty column
    df["mail_id"] = range(0, len(df))  # add a unique ID for each email

    # Preprocess emails
    print("Preprocessing emails...")
    for mail_id in range(0, len(df)):
        e = df.iloc[mail_id]
        if isinstance(e["body"], str):
            body, urls = preprocessor.preprocessURLsPlainText(str(e["body"]), truncate_URLs=False)
            headers = "To: " + str(e["receiver"]) + "\nFrom: " + str(e["sender"]) + "\nDate: " + str(e["date"])
            df.iloc[mail_id, df.columns.get_loc("body")] = body.replace('\n', '\\n')
            df.iloc[mail_id, df.columns.get_loc("urls")] = " ".join(urls)  # put the list in a single string
            df.iloc[mail_id, df.columns.get_loc("headers")] = headers.replace('\n', '\\n')
        else:
            print(e)
            continue

    df.drop_duplicates("body", inplace=True)
    df["date"].apply(convert_to_datetime)
    phishing_records = df[df["label"] == 1]
    legit_records = df[df["label"] == 0]

    print("Dataset " + dataset_name)
    print("# Records: " + str(len(phishing_records) + len(legit_records)),
          "(Legit = " + str(len(legit_records)) + ", Phishing = " + str(len(phishing_records)) + ")")
    print("########\n")
    return legit_records, phishing_records


def get_df_with_geolocation(emails_df):
    # emails_df = df.copy(deep=False)
    emails_df["url_location"] = ""
    """
    for i in range(0, len(emails_df)):
        mail = emails_df.iloc[i]
        mail_urls = [] if len(mail["urls"]) == 0 else mail["urls"].split(" ")  # explode the string into a list

        if len(mail_urls) == 0:
            print(f"No URL, skipping email with ID {i}")
            continue
        else:
            url_to_analyze = mail_urls[0]  # for now, we take the first URL
            url_fullhostname = get_fullhostname(url_to_analyze)  # =protocol + fqdn, w/o path
            print(f"-- Mail {i}, analyzing URL: {url_fullhostname}")
            domain_location = get_dns_info(url_fullhostname)
            emails_df.iloc[i, emails_df.columns.get_loc("url_location")] = domain_location
    """
    return emails_df


if __name__ == "__main__":
    load_dotenv()
    base_path = os.path.join("evaluation", "datasets", "zenodo")
    datasets = ["Nazario.csv", "SpamAssassin.csv", "Nigerian_Fraud.csv"]

    phishing_records_df = pd.DataFrame()
    legit_records_df = pd.DataFrame()
    for d in datasets:
        legit, phish = get_preprocessed_dataset(d)
        legit_records_df = pd.concat([legit_records_df, legit])
        phishing_records_df = pd.concat([phishing_records_df, phish])

    # Write the filtered records to 2 CSV files
    fieldnames_csv = ["mail_id", "headers", "date", "sender", "receiver", "subject", "body", "urls", "url_location", "label"]
    for label in ["phishing", "legit"]:
        output_file = os.path.join(base_path, "..", label + ".csv")
        # filtered_df = pd.DataFrame(columns=fieldnames_csv)  # initialize empty dataframe
        records = phishing_records_df if label == "phishing" else legit_records_df
        records = records[records['urls'].apply(len) > 0]  # only get the emails with at least 1 url

        MAX_ELEMENTS = 2000  # maximum number of legitimate and phishing emails (each)
        records = records.sort_values("date", ascending=False)[:MAX_ELEMENTS]  # get the most recent MAX_ELEMENTS emails
        records = get_df_with_geolocation(records)  # add the geolocation information to each email
        records.to_csv(output_file, columns=fieldnames_csv, index=False, escapechar="\\")  # save the df to a csv

        print(f"{len(records)} filtered {label} records saved to {output_file}")
