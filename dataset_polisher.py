import os
import csv
import re
from datetime import datetime
import pandas as pd


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


def get_filtered_dataset(dataset_name):
    df = pd.read_csv(os.path.join(base_path, dataset_name))
    original_records_count = len(df)

    df.drop_duplicates("body", inplace=True)
    df["date"].apply(convert_to_datetime)
    #df["date"] = pd.to_datetime(df["date"], format='mixed')
    phishing_records = df[df["label"] == 1]
    legit_records = df[df["label"] == 0]

    print("Dataset " + dataset_name)
    print("Initial records: " + str(original_records_count),
          " - Filtered records: " + str(len(phishing_records) + len(legit_records)),
          "Legit = " + str(len(legit_records)) + ", Phishing = " + str(len(phishing_records)))
    print("########\n")
    return legit_records, phishing_records


if __name__ == "__main__":
    base_path = os.path.join("evaluation", "datasets", "zenodo")
    datasets = ["Nazario.csv", "SpamAssassin.csv", "Nigerian_Fraud.csv"]

    phishing_records_df = pd.DataFrame()
    legit_records_df = pd.DataFrame()
    for d in datasets:
        legit, phish = get_filtered_dataset(d)
        legit_records_df = pd.concat([legit_records_df, legit])
        phishing_records_df = pd.concat([phishing_records_df, phish])

    # Write the filtered records to 2 CSV files

    fieldnames_csv = ['sender', 'receiver', 'date', 'subject', 'body', 'urls', 'label']
    for label in ["phishing", "legit"]:
        output_file = os.path.join(base_path, "..", label + ".csv")
        # filtered_df = pd.DataFrame(columns=fieldnames_csv)  # initialize empty dataframe
        records = phishing_records_df if label == "phishing" else legit_records_df
        records = records[records['urls'].apply(int) > 0]

        MAX_ELEMENTS = 2000  # maximum number of legitimate and phishing emails (each)
        records = records.sort_values("date", ascending=False)[:MAX_ELEMENTS]
        records.to_csv(output_file, columns=fieldnames_csv, sep=";")

        print(f"{len(records)} filtered {label} records saved to {output_file}")

