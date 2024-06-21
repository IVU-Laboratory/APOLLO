import openai
import json
import os
import asyncio
# from g4f.client import Client
from g4f.Provider import RetryProvider, Bing, Phind, FreeChatgpt, Liaobots, You, Llama, Theb

SEED = 42
MODEL = "gpt-4o-2024-05-13"  # "gpt-4"  # "gpt-3.5-turbo-1106"
MODEL_BATCH = "gpt-4o-2024-05-13"
TEMPERATURE = 0.0001

# Set a global client for GPT4free
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
"""client = Client(
    provider=RetryProvider([Bing, Phind, FreeChatgpt, You, Llama, Theb], shuffle=False)  # https://github.com/xtekky/gpt4free
)"""
global client


def classify_email(email_input, feature_to_explain=None, url_info=None, explanations_min=3, explanations_max=6,
                   model=MODEL):
    # Initial Prompt
    messages = [
        {"role": "system", "content": f'''You are a cybersecurity and human-computer interaction expert that has the goal to detect
        if an email is legitimate or phishing and help the user understand why a specific email is dangerous (or genuine), in order
        to make more informed decisions.
        The user will submit the email (headers + subject + body) optionally accompanied by information of the URLs in the email as:
        - server location;
        - VirusTotal scans reporting the number of scanners that detected the URL as harmless;
        - number of blacklists in which the linked domain was found.

        Your goal is to output a JSON object containing:
        - The classification result (label).
        - The probability in percentage of the email being phishing (0%=email is surely legitimate, 100%=email is surely phishing) (phishing_probability).
        - A list of persuasion principles that were applied by the alliged attacker (if any); each persuasion principle should be an object containing:
            the persuasion principle name (authority, scarcity, etc.),
            the part of the email that makes you say that persuasion principle is being applied;
            a brief rationale for each principle.
        - A list of {explanations_min} to {explanations_max} features that could indicate the danger (or legitimacy) of the email; the explanations must be understandable by users with no cybersecurity or computers expertise.


        Desired format:
        label: <phishing/legit>
        phishing_probability: <0-100%>
        persuasion_principles: [array of persuation principles, each having: {{name, specific sentences, rationale}} ]
        explanation: [array of {explanations_min}-{explanations_max} features explained]'''
         }
    ]
    # User input (email)
    headers = str(email_input["headers"])
    subject = email_input["subject"]
    body = email_input["body"]
    email_prompt = f'''Email:
          """
          [HEADERS]
            {headers}
          [\HEADERS]
          [SUBJECT] {subject} [\SUBJECT]
          [BODY]
          {body}
          [\BODY]
          """
          '''
    # Add the url_info if it exists
    if url_info is not None:
        email_prompt += f"""

          ######

          URL Information:
          {str(url_info)}"""

    messages.append({"role": "user", "content": email_prompt})
    # Get the classification response
    # client = Client()
    response = client.chat.completions.create(
        model=model,
        seed=SEED,
        temperature=TEMPERATURE,
        messages=messages,
        response_format={"type": "json_object"}
    )
    classification_response = response.choices[0].message.content

    messages.append({"role": "assistant",
                     "content": f"{classification_response}"})  # attach the response string for the second prompt

    # Try getting the JSON object from the response
    try:
        classification_response = json.loads(classification_response)
    except:
        print("Invalid JSON format in the response")
        return classification_response, ""

    if "label" in classification_response:
        predicted_label = classification_response['label']
        if predicted_label == "legit":
            # If the classification == legit, then exit the function
            return classification_response, "The email is genuine"
        else:
            # Otherwise, we ask GPT to produce the warning message
            if feature_to_explain is None:
                # Automatically take the most relevant feature
                messages.append(
                    {"role": "user", "content": """
              Now take the most relevant feature among the ones in your explanations and construct a brief explanation message (max 50 words) directed to naive users (with no knowledge of cybersecurity) that will follow this structure:`
              1. description of the most relevant phishing feature
              2. explanation of the hazard
              3. consequences of a successful phishing attack
              For example, a message that explains that a URL in the email (PHISHING_URL) is imitating another legitimate one (SAFE_URL), would be:
              "The target URL [PHISHING_URL] is an imitation of the original one, [SAFE_URL]. This site might be intended to take you to a different place. You might be disclosing private information.”.
              Another example of explanation about the domain of a website being suspiciously young would be:
              "This website is very young (created [N] days ago). Fraudulent websites have a similar age. There is a potential risk of being cheated if you proceed."
              Another example of explaining that the email is suspicious because a domain linked in the email is hosted in a country with bad reputation would be:
              "The host of the target website is in [COUNTRY], which is where most attacks originate. Sharing your private information here is risky."

              Desired format:
              [description of the feature]. [hazard explanation]. [consequences of a successful attack].
              """}
                )
            else:
                # Be primed about the feature to explain
                messages.append(
                    {"role": "user", "content": f"""
              Consider that the previous email is suspicious because {feature_to_explain["description"]}: construct a brief explanation message (max 50 words) directed to naive users (with no knowledge of cybersecurity) that will follow this structure:`
              1. description of the feature (in this case {feature_to_explain["name"]})
              2. explanation of the hazard
              3. consequences of a successful phishing attack
              For example, a message that explains that a URL in the email (PHISHING_URL) is imitating another legitimate one (SAFE_URL), would be:
              "The target URL [PHISHING_URL] is an imitation of the original one, [SAFE_URL]. This site might be intended to take you to a different place. You might be disclosing private information.”.
              Another example of explanation about the domain of a website being suspiciously young would be:
              "This website is very young (created [N] days ago). Fraudulent websites have a similar age. There is a potential risk of being cheated if you proceed."
              Another example of explaining that the email is suspicious because a domain linked in the email is hosted in a country with bad reputation would be:
              "The host of the target website is in [COUNTRY], which is where most attacks originate. Sharing your private information here is risky."

              Desired format:
              [description of the feature]. [hazard explanation]. [consequences of a successful attack].
              """}
                )
            response_2 = client.chat.completions.create(
                model=model,
                seed=SEED,
                temperature=TEMPERATURE,
                messages=messages
            )
            classification_response = response.choices[0].message.content
            explanation_response = response_2.choices[0].message.content
        return classification_response, explanation_response
    else:  # Error: response in wrong format
        print("The response does not contain the predicted label (phishing/non-phishing)")
        return classification_response, ""


def initialize_openAI():
    openai.api_key = os.getenv('OPENAI_API_KEY')
    global client
    client = openai.OpenAI()  # use OpenAI apis as the client


def classify_email_minimal(email_input, url_info=None, model=MODEL):
    email_prompt = '''You are a cybersecurity and human-computer interaction expert that has the goal to detect
           if an email is legitimate or phishing and help the user understand why a specific email is dangerous (or genuine), in order
           to make more informed decisions.
           The user will submit the email (headers + subject + body) optionally accompanied by information of the URLs in the email as:
           - server location;
           - VirusTotal scans reporting the number of scanners that detected the URL as harmless, undetected, suspicious, malicious;
           - number of blacklists in which the linked domain was found.\n
           Your goal is to output a JSON object containing:
           - The classification result (label).
           - The probability in percentage of the email being phishing (0%=email is surely legitimate, 100%=email is surely phishing) (phishing_probability).\n
           Desired format:
           {
            label: <phishing/legit>
            phishing_probability: <0-100%>
           }\n
           Answer with the JSON object exclusively.\n
           '''

    # User input (email)
    headers = str(email_input["headers"])
    subject = email_input["subject"]
    body = email_input["body"]
    email_prompt += f'''\n\nEmail:\n
             """
             [HEADERS]
               {headers}
             [\HEADERS]
             [SUBJECT] {subject} [\SUBJECT]
             [BODY]
             {body}
             [\BODY]
             """
             '''
    # Add the url_info if it exists
    if url_info is not None:
        email_prompt += f"""

             ######

             URL Information:
             {str(url_info)}"""

    messages = [{"role": "user", "content": email_prompt}]
    try:
        # Get the classification response
        response = client.chat.completions.create(
            model=model,
            seed=SEED,
            temperature=TEMPERATURE,
            messages=messages,
            response_format={"type": "json_object"}
        )
        classification_response = response.choices[0].message.content
        # Try getting the JSON object from the response
    except Exception as e:
        print("Error in making the request to the LLM:")
        print(e)
        return "", None
    try:
        classification_response = json.loads(classification_response)
    except Exception as e:
        print("Invalid JSON format in the response:", classification_response)
        print(e)
        return "Invalid format", None

    if "label" in classification_response and "phishing_probability" in classification_response:
        predicted_label = classification_response['label']
        probability = classification_response['phishing_probability']
        return predicted_label, probability
    else:
        print("The response does not contain the predicted label (phishing/non-phishing)")
        return classification_response, ""


def generate_batch_requests_file(emails_df, output_file_path):
    assistant_prompt = '''You are a cybersecurity and human-computer interaction expert that has the goal to detect
           if an email is legitimate or phishing and help the user understand why a specific email is dangerous (or genuine), in order
           to make more informed decisions.
           The user will submit the email (headers + subject + body) optionally accompanied by information of the URLs in the email as:
           - server location;
           - VirusTotal scans reporting the number of scanners that detected the URL as harmless, undetected, suspicious, malicious;
           - number of blacklists in which the linked domain was found.\n
           Your goal is to output a JSON object containing:
           - The classification result (label).
           - The probability in percentage of the email being phishing (0%=email is surely legitimate, 100%=email is surely phishing) (phishing_probability).\n
           Desired format:
           {
            label: <phishing/legit>
            phishing_probability: <0-100%>
           }\n
           Answer with the JSON object exclusively.\n
           '''
    requests = []
    for i in range(0, len(emails_df)):
        mail = emails_df.iloc[i]
        email_prompt = get_email_prompt(mail, mail["url_info"])
        messages = [{"role": "system", "content": assistant_prompt},
                    {"role": "user", "content": email_prompt}]
        mail_ID = str(mail["mail_id"])
        true_label = str(int(mail["label"]))
        request = {
            "custom_id": mail_ID + "_" + true_label,  # the ID format must be = "mailID_label"
            "method": "POST",
            "url": "/v1/chat/completions",
            "body": {
                "model": MODEL_BATCH,
                "seed": SEED,
                "temperature": TEMPERATURE,
                "response_format": {"type": "json_object"},
                "messages": messages
            }
        }
        requests.append(request)
    # Write the requests on a JSONL file
    with open(output_file_path, 'w') as f:
        for r in requests:
            f.write(json.dumps(r) + "\n")
        print("Requests file created at ", output_file_path)


def get_email_prompt(email_input, url_info=None):
    # User input (email)
    headers = str(email_input["headers"])
    subject = email_input["subject"]
    body = email_input["body"]
    email_prompt = f'''\n\nEmail:\n
        """
        [HEADERS]
        {headers}
        [\HEADERS]
        [SUBJECT] {subject} [\SUBJECT]
        [BODY]
        {body}
        [\BODY]
        """
    '''
    # Add the url_info if it exists
    if url_info is not None:
        email_prompt += f"""

             ######

             URL Information:
             {str(url_info)}"""
    return email_prompt


def launch_batch(batch_file, description="Evaluation"):
    # Upload the file with the requests
    batch_input_file = client.files.create(
        file=open(batch_file, "rb"),
        purpose="batch"
    )
    print("Uploaded file " + batch_file + " successfully")
    # Start the batch 
    batch = client.batches.create(
        input_file_id=batch_input_file.id,
        endpoint="/v1/chat/completions",
        completion_window="24h",
        metadata={
            "description": description
        }
    )
    print("Batch started!")
    print(batch)
    with open("batch_info.json", "w") as info_file:
        json_object = {"batch_id": batch.id, "input_file": batch.input_file_id,
                       "created_at": batch.created_at}  # , "expiration": batch.expiration}
        info_file.write(json.dumps(json_object))
    return batch.id  # return the batch ID for further inspection


def check_batch_status(batch_id):
    batch = client.batches.retrieve(batch_id)
    print("Batch status:")
    print(batch)
    return batch.output_file_id  # returns the output ID, if the batch was successfully executed


def retrieve_batch_results(results_file_id):
    content = client.files.content(results_file_id)
    return content.response.text


"""try:
    response = content.response.text
    lines = str.split(response, "\n")  # get the indiviudal lines of the jsonl results file in response
    results = []
    for line in lines:
        if :
            json_object = json.loads(line)
            try:
                model_response = json_object["response"]["body"]["choices"][0]["message"]["content"]
                model_response = json.loads(model_response)
                result = {}
                results.append(result)
            except json.decoder.JSONDecodeError as e:
                print(e)
                continue
    return results
except Exception as e:
    print(e)
    return []"""
