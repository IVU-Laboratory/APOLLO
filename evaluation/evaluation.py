import preprocessor
import url_enricher
import llm_prompter
import os
import pandas as pd
from dotenv import load_dotenv
import csv
import time


# gpt-4-1106-preview
# No URL
# End index legit = 1726
# End index phishing = 3230

# With URL
# End index legit = 735
# End index phishing = 2750

START_INDEX = 0
END_INDEX = START_INDEX + 820
# Add "True" to ENRICH_URL to create a batch of requests that include URL Info
ENRICH_URL = [False]
QUANTILE = 100

GENERATE = True
LAUNCH = False
RETRIEVE = False


def main():
    requests_batch_file = f"requests_URL_{str(QUANTILE)}.jsonl" if ENRICH_URL else "requests_noURL.jsonl"  
    results_file = f"results_URL_{str(QUANTILE)}.jsonl" if ENRICH_URL else "results_noURL.jsonl"
    # GENERATE THE REQUESTS
    if GENERATE:
        load_dotenv(os.path.join("..", ".env"))
        llm_prompter.set_api_key()  # Statically set the API key for OpenAI
        fieldnames = ["mail_id", "label", "prob", "true_label"]

        # get the emails from phishing.csv and legit.csv 
        emails_df = load_emails(["legit.csv", "phishing.csv"])

        # Create a jsonl file with the batch requests for OpenAI 
        llm_prompter.generate_batch_requests_file(emails_df, requests_batch_file)
    if LAUNCH:
        description = "Evaluation"
        batch_id, _ = llm_prompter.launch_batch(requests_batch_file, description)
    if RETRIEVE:
        _, file_id = llm_prompter.check_batch_status(batch_id)
        results = llm_prompter.retrieve_batch_results(file_id)
        write_results_to_file(results, results_file)


def load_emails(csv_files):
    ## Load emails
    emails_df = pd.DataFrame()
    print("Loading emails...")
    for file_name in csv_files:
        df = pd.read_csv(os.path.join('datasets', file_name), sep=",")
        emails_df = pd.concat([emails_df, df])

    # Get only emails in the specified range
    emails_df = emails_df.iloc[START_INDEX:END_INDEX]
    for enrich_url in ENRICH_URL:
        # print("Enrich URL = " + ("True" if enrich_url else "False"))
        already_processed = load_already_classified_emails(enrich_url)  # get a dataframe with the already processed emails 
        for i in range(0, len(emails_df)):
            mail = emails_df.iloc[i]
            mail_urls = [] if len(mail["urls"]) == 0 else mail["urls"].split(" ")  # explode the string into a list
            # If email has no URL OR if email was already processed, skip it
            if len(mail_urls) == 0 or (already_processed["mail_id"] == mail["mail_id"]).any():                 
                emails_df.drop(i)
            else:
                # Get additional information about URLs in the email
                if enrich_url:
                    # url_to_analyze = mail_urls[0]  # for now, we take the first URL
                    url_info = url_enricher.get_dummy_values(QUANTILE, mail["url_location"], mail["label"])  # url_enricher.get_url_info(url_to_analyze)
                else:
                    url_info = None
                emails_df.iloc[i]["url_info"] = url_info
    return emails_df


def load_already_classified_emails(enrich_url):
    if (enrich_url):
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


def read_batch_putput_file(file_path):
    batch_output = pd.read_json(path_or_buf=file_path, lines=True)
    results = pandas.DataFrame()
    for line in batch_output:
        if line.response.status_code == 200:
            response = line.response.body.choices.[0].message.content
             try:
                classification_response = json.loads(classification_response)
                y_label = classification_response["label"]
                y_prob = classification_response["phishing_probability"]
                result = {"mail_id": mail["mail_id"], "label": y_label, "prob": y_prob, "true_label": str(mail["label"])}
                print(f"{result['mail_id']},{result['label']},{result['prob']},{result['true_label']}")
                results.append(result)
            except Exception e:
                print(e)
                print(response)
    return results


def write_results_to_file(output_file):
    with open(file_to_open, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow(result)


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

