import preprocessor
import url_enricher
import llm_prompter
import os
from dotenv import load_dotenv

ENRICH_URL = True
MODEL = "gpt-4o-2024-05-13"


def main():
    load_dotenv()
    llm_prompter.initialize_openAI()  # Statically set the API key for OpenAI

    email_filename = input("Please insert the name of the email file to classify (.eml format)")
    # Open and preprocess an email
    with open(email_filename, "rb") as email_byes:
        mail = email_byes.read()
        mail = preprocessor.preprocess_email(mail)
        # Print or use the extracted subject, header, and body as needed
        """print("Subject:", mail["subject"])
        print("Headers:")
        print(mail["headers"])
        print("Body:")
        print(mail["body"])
        print("URLS:")
        print(mail["urls"])"""
        # Gather additional information about URLs in the email
    if len(mail["urls"]) > 0 and ENRICH_URL:
        print("Retrieving additional URL information...")
        # Call remote API to gather online URL information
        url_to_analyze = mail["urls"][0]  # for now, we take the first URL
        url_info = url_enricher.get_url_info(url_to_analyze)
    else:
        url_info = None
    print(f"Classifying the email with GPT... (model = {MODEL})\n")
    # Call GPT for email phishing classification
    classification_response, warning_msg = llm_prompter.classify_email(mail, url_info, model=MODEL)
    print(classification_response)
    print(warning_msg)


if __name__ == "__main__":
    main()
