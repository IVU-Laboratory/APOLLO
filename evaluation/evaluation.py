import preprocessor
import url_enricher
import llm_prompter
import os
import pandas as pd
from dotenv import load_dotenv
import csv

GPT_MODEL = "gpt-4-1106-preview"  # "gpt-3.5-turbo-0613"

START_INDEX = 1731
END_INDEX = START_INDEX + 1


def main():
    load_dotenv(os.path.join("..", ".env"))
    llm_prompter.set_api_key()  # Statically set the API key for OpenAI

    y_results_url = []
    y_results_no_url = []
    emails_df = pd.DataFrame()
    print("Loading emails...")
    # load emails
    for file_name in ["legit.csv", "phishing.csv"]:
        df = pd.read_csv(os.path.join('datasets', file_name))
        df.drop_duplicates("body", inplace=True)
        emails_df = pd.concat([emails_df, df])
    emails_df["headers"] = ""  # add empty column
    emails_df["mail_id"] = range(0, len(emails_df))  # add a unique ID for each email
    emails_df = emails_df.iloc[START_INDEX:END_INDEX]

    print("Preprocessing emails...")
    # preprocess emails
    for mail_id in range(0, len(emails_df)):
        e = emails_df.iloc[mail_id]
        body, urls = preprocessor.preprocessURLsPlainText(e["body"])
        headers = "To: " + e["receiver"] + "\nFrom: " + e["sender"] + "\nDate: " + e["date"]
        emails_df.iloc[mail_id, emails_df.columns.get_loc("body")] = body
        emails_df.iloc[mail_id, emails_df.columns.get_loc("urls")] = ' '.join(urls)  # put the list into a single string
        emails_df.iloc[mail_id, emails_df.columns.get_loc("headers")] = headers

    print("Classifying emails...")
    for enrich_url in [True, False]:
        print("Enrich URL = " + ("True" if enrich_url else "False"))
        for mail_id in range(0, len(emails_df)):
            mail = emails_df.iloc[mail_id]
            print("- Processing email " + str(mail["mail_id"]))
            # Get additional information about URLs in the email
            mail_urls = [] if mail["urls"] == "" else mail["urls"].split(" ")  # explode the string into a list
            if enrich_url:
                if len(mail_urls) == 0:  # Then the result is already stored in the no_url counterpart
                    # print([d for d in y_results_no_url if d['mail_id'] == mail_id])
                    print("Already computed")
                    continue
                else:
                    # Call remote API to gather online URL information
                    url_to_analyze = mail_urls[0]  # for now, we take the first URL
                    print("-- Analyzing URL: " + url_to_analyze)
                    url_info = url_enricher.get_url_info(url_to_analyze)
            else:
                url_info = None

            # Call GPT-4 for email phishing classification (automatic feature detection)
            print("-- Classifying with GPT:")
            # y_label, y_prob = None, None
            y_label, y_prob = llm_prompter.classify_email_minimal(mail, url_info, model=GPT_MODEL)
            if y_prob is None:  # then there's an error in the response
                continue
            result = {"mail_id": mail["mail_id"], "label": y_label, "prob": y_prob, "true_label": str(mail["label"])}
            print(result)
            if enrich_url:
                y_results_url.append(result)
            else:
                y_results_no_url.append(result)
        print("\n\n####\n\n")

    print("Saving results to file...")
    fieldnames = ["mail_id", "label", "prob", "true_label"]
    with open(os.path.join('results', 'url_enriched.csv'), 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        for row in y_results_url:
            writer.writerow(row)

    with open(os.path.join('results', 'no_url_enriched.csv'), 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)  # , lineterminator='\n')
        for row in y_results_no_url:
            writer.writerow(row)


if __name__ == "__main__":
    main()
