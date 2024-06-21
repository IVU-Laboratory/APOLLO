import preprocessor
import url_enricher
import llm_prompter
import os
import pandas as pd
from dotenv import load_dotenv
import csv
import time
import json

# gpt-4-1106-preview
# No URL
# End index legit = 1726
# End index phishing = 3230

# With URL
# End index legit = 735
# End index phishing = 2750

START_INDEX = 1000
END_INDEX = START_INDEX + 10

# Set ENRICH_URL to True to create a batch of requests that include URL Info
ENRICH_URL = False
QUANTILE = 100

GENERATE = False
LAUNCH = False
RETRIEVE = True

fieldnames = ["mail_id", "label", "prob", "true_label"]


def main():
    if ENRICH_URL:
        file_name = f"requests_URL_{START_INDEX}-{END_INDEX}_time={str(QUANTILE)}.jsonl"
    else:
        file_name = f"requests_noURL_{START_INDEX}-{END_INDEX}.jsonl"
    requests_batch_file = os.path.join("batches", "requests", file_name)
    results_file = os.path.join("batches", "results", file_name)
    # Initialize Open AI parameters
    load_dotenv(os.path.join("..", ".env"))
    llm_prompter.initialize_openAI()  # Statically set the API key for OpenAI

    batch_id = None  # initialize variable
    if GENERATE:  # Generate the requests
        # get the emails from phishing.csv and legit.csv 
        emails_df = load_emails(["legit.csv", "phishing.csv"])
        # Create a jsonl file with the batch requests for OpenAI
        llm_prompter.generate_batch_requests_file(emails_df, requests_batch_file)
    if LAUNCH:  # Launch batch
        batch_id = llm_prompter.launch_batch(requests_batch_file)
    if RETRIEVE:  # Retrieve results
        if batch_id is None:  # if there is no batch ID set, ask it to the user
            batch_id = input("Enter the batch ID (found in the batch_info.txt file):")
        file_id = llm_prompter.check_batch_status(batch_id)
        if file_id is not None:  # if the process executed successfully
            # Retrieve the results
            batch_output = llm_prompter.retrieve_batch_results(file_id)
            results = read_batch_putput_file(batch_output)
            results.to_csv(results_file)


def load_emails(csv_files):
    emails_df = pd.DataFrame()
    print("Loading emails...")
    for file_name in csv_files:
        df = pd.read_csv(os.path.join('datasets', file_name), sep=",")
        emails_df = pd.concat([emails_df, df])

    # Get only emails in the specified range
    emails_df = emails_df.iloc[START_INDEX:END_INDEX]
    emails_df["url_info"] = None  # initialize empty column for the URL information

    already_processed = load_already_classified_emails(ENRICH_URL)  # get a dataframe with the already processed emails
    for i in range(0, len(emails_df)):
        mail = emails_df.iloc[i]
        mail_urls = [] if len(mail["urls"]) == 0 else mail["urls"].split(" ")  # explode the string into a list
        # If email has no URL OR if email was already processed, skip it
        if len(mail_urls) == 0 or (already_processed["mail_id"] == mail["mail_id"]).any():
            emails_df = emails_df.drop(i)
        else:
            # Get additional information about URLs in the email
            if ENRICH_URL:
                # url_to_analyze = mail_urls[0]  # for now, we take the first URL
                url_info = url_enricher.get_dummy_values(QUANTILE, mail["url_location"], mail["label"])  # url_enricher.get_url_info(url_to_analyze)
                emails_df.iloc[i, emails_df.columns.get_loc("url_info")] = url_info
    return emails_df


def load_already_classified_emails(enrich_url):
    if enrich_url:
        file_name = os.path.join('results', 'url_enriched_' + str(QUANTILE) + '.csv')
    else:
        file_name = os.path.join('results', 'no_url_enriched.csv')
    
    if os.path.exists(file_name):
        y_results = pd.read_csv(file_name, names=fieldnames)
    else:
        y_results = pd.DataFrame(columns=fieldnames)  # empty dataframe
    # else:
    #    open(url_enriched_file, 'a')  # create empty file
    #    y_results_url = pd.DataFrame(columns=fieldnames)
    return y_results


def read_batch_putput_file(batch_result):
    lines = str.split(batch_result, "\n")  # get the indiviudal lines of the jsonl results file in response
    results = []
    for line in lines:
        if len(line) > 0:  # be sure each line is not empty
            try:
                line = json.loads(line)
                if line["response"]["status_code"] == 200:
                    # the request ID was = "{mailID}_{label}"
                    mailID = str.split(line["custom_id"], "_")[0]
                    true_label = str.split(line["custom_id"], "_")[1]
                    try:
                        # get the response content
                        classification_response = line["response"]["body"]["choices"][0]["message"]["content"]
                        classification_response = json.loads(classification_response)
                        y_label = classification_response["label"]
                        y_prob = classification_response["phishing_probability"]
                        result = {"mail_id": mailID, "label": y_label, "prob": y_prob, "true_label": true_label}
                        print(f"{result['mail_id']},{result['label']},{result['prob']},{result['true_label']}")
                        results.append(result)
                    except Exception as e:
                        # the result is discarded
                        print(e)
                        print(json.dumps(line))
            except Exception as e:
                print(e)
    results_df = pd.DataFrame(results)
    return results_df


if __name__ == "__main__":
    main()
    


"""
def add_missing_records_to_no_url_enriched_file():
    # Read the CSV files into pandas DataFrames
    no_url_df = pd.read_csv("no_url_enriched.csv")
    url_df = pd.read_csv("url_enriched.csv")

    # Find mail_ids present in no_url_df but missing in url_df
    missing_mail_ids = set(no_url_df['mail_id']) - set(url_df['mail_id'])

    # Filter rows from no_url_df where mail_id is in missing_mail_ids
    filtered_rows = no_url_df[no_url_df['mail_id'].isin(missing_mail_ids)]

    # Append the filtered rows to url_df and write to a new file url_enriched.csv
    url_df = url_df.append(filtered_rows)

    # Write the updated DataFrame to a new CSV file
    url_df.to_csv("url_enriched.csv", index=False)
"""

