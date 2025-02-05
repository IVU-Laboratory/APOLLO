
# APOLLO (Advanced Phishing preventiOn with Large Language model-based Oracle)

APOLLO is a tool written in Python 3.10.12 and powered by GPT-4o ([gpt-4o-2024-13-5]([url](https://platform.openai.com/docs/models/gpt-4o))) to:

- **classify** an email as **phishing** or legitimate, and
- **generate an explanation** for the user in the case of a phishing email.

The tool is accessible by using the _main.py_ script and is composed of three modules: _preprocessor.py_ (which preprocesses emails), _url_enricher.py_ (which gathers online information about any URLs in emails), and _llm_prompter.py_ (which interacts with GPT-4o).

A demo of the tool is also available as a Jupyter notebook in the file _APOLLO.ipynb_.

APOLLO takes in input an email in _.eml format_ and, thanks to the preprocessor module, removes any HTML tag and saves information about the links in the email (as done in [1]). To overcome the knowledge cut-off of GPT-4o, we enriched the link with online information. Specifically, we query the VirusTotal API to check if the link is malicious and BigDataCloud to see the server location, useful for the explanation phase. Finally, the email link and this additional information are used to fill in two templates of GPT-4o prompts, which allow APOLLO to classify the email and generate the explanation. 

![APOLLO sequence diagram](APOLLO_UML.png "Sequence diagram of APOLLO.")
<p style="text-align: center;">Sequence diagram of APOLLO. The tool takes an email file as input and returns the explanation message to insert in a warning dialog if the email resulted to be phishing according to the GPT model.
</p>

The core of the tool is the set of the GPT-4o prompts, thus we devoted particular care to manually designing and iteratively refining them according to the best practices of prompt-engineering [2-4]. Notably, we followed a few-shot prompting approach, as also suggested by OpenAI [4]. The generated explanations follow the structure defined in [5]: “Feature description + Hazard Explanation + Consequences of not complying with the warning”. This structure is grounded on warning theory for the design of warning messages [6]. Moreover, the generated explanations revolve around a set of email features that are valuable for users in making decisions regarding phishing content [5,7] i.e., are:

- (1) Top-Level Domain in the URL is Mispositioned (e.g., as in the URL “www.amazon.com.cz”); 
- (2) the URL is an IP address; 
- (3) Mismatch between the displayed and actual link; 
- (4) the URL points to a very young domain.

# Supplementary material

## Classification evaluation 

In the _Classification evaluation_ folder, there are the files related to the evaluation of the tool with GPT-4o. 
Specifically, the _results_ subfolder contains:
- the results and statistical tests of the evaluation process ("predicted_labels", 
"predicted_probabilities", and "repeated_evaluation"); 
- the results of the analysis conducted on VirusTotal ("VirusTotal ranges"). 

To reproduce the results, the following steps must be done:

- Be sure that the .env file is correctly included in the root folder and contains the required API keys: copy the 
_.env.example_ file in a new file named _.env_,  and there set the API keys for the required services: 
  - OPENAI_API_KEY is the key from OpenAI (https://platform.openai.com/docs/overview), 
  - (not necessary) VT_API is the key for VirusTotal (https://www.virustotal.com/gui/home/),
  - DNS_API is the key for BigDataCloud (https://www.bigdatacloud.com/)
- (Optional) If the datasets must be changed, load your datasets in the _"Classification evaluation/datasets"_ folder; 
then edit the _"Classification evaluation/dataset_polisher.py"_ script by referring to the updated datasets in the main function. 
Ensure that your custom datasets respect the required format of the datasets used in this project. 
- Run the _"Classification evaluation/evaluation.py"_ script - be careful, as it will have a cost on your API credit of OpenAI.  
You can change the **evaluations** variable to (temporarily or not) exclude some of the 14 rounds of evaluation (consider that, by default,
_DATASET_LENGTH * num rounds_ evaluations will be performed).
You are advised to read the [paper](https://arxiv.org/abs/2410.07997) carefully for more details about the data used in the different rounds.
- Your results will be found in the "_Classification evaluation/results_" folder. Be sure that no previous result is overwritten by the execution. 

## Warning evaluation

In the _Warning evaluation_ folder there are all the files related to the user study conducted to evaluate the warning 
dialogs produced by APOLLO. Specifically: 
- In the file _emails+warnings.zip_ are stored the emails (in .html format) to which users in the study "Can LLMs help protect users from phishing attacks? An exploratory study" were exposed, together with the warnings shown (in .png format). Warnings are named WX.png, where X is the experimental condition (from 1 to 4); emails name include the warning name to match them with the warnings that were shown together.

- The "_Baseline Comparison - Stat test details.xls_" file contains the results of the statistical comparison performed between our 4 experimental conditions (W1-W4) and the 4 baselines (manual explanation + chrome + edge + firefox).

- The "_Experimental Conditions - Stat details.xlsx_" file contains 2 sheets with: 1) the descriptive statistical details of the 4 experimental conditions (average and standard deviation of W1-W4) and 2) the results of the friedman test comparing the 4 experimental conditions pairwise.


# Cite this work

G. Desolda, F. Greco, and L. Viganò (2024). _APOLLO: A GPT-based tool to detect phishing emails and generate explanations that warn users._ Preprint: https://arxiv.org/abs/2410.07997


# References

[1] Misra, K. and Rayz, J. T. 2022. LMs go Phishing: Adapting Pre-trained Language Models to Detect Phishing Email.

[2] Liu, P., Yuan, Q., Fu, J., Jiang, Z., Hayashi, H. and Neubig, G. 2023. Pre-train, Prompt, and Predict: A Systematic Survey of Prompting Methods in Natural Language Processing.ACM Comput. Surv., 55, 9, Article 195. https://doi.org/10.1145/3560815

[3] DAIR.AI Prompt Engineering Guide. https://www.promptingguide.ai

[4] Shieh, J. Best practices for prompt engineering with OpenAI API. OpenAI https://help.openai.com/en/articles/6654000-best-practices-for-prompt-engineering-with-openai-api

[5] Desolda, G., Aneke, J., Ardito, C., Lanzilotti, R. and Costabile, M. F. 2023. Explanations in warning dialogs to help users defend against phishing attacks.Explanations in warning dialogs to help users defend against phishing attacks, 176 2023/08/01, 103056. https://www.sciencedirect.com/science/article/pii/S1071581923000654

[6] Bauer, L., Bravo-Lillo, C., Cranor, L. and Fragkaki, E. 2013. Warning Design Guidelines (CMU-CyLab-13-002).

[7] Buono, P., Desolda, G., Greco, F. and Piccinno, A.2023. Let warnings interrupt the interaction and explain: designing and evaluating phishing email warnings. In Proceedings of the CHI Conference on Human Factors in Computing Systems (Short Let warnings interrupt the interaction and explain: designing and evaluating phishing email warnings), April 2023, 2023, Hamburg Germany. ACM, 1-6. 
