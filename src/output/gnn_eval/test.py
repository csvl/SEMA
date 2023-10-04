from npf_web_extension.app import export


with open('./ml_eval_stats.csv', 'r') as f:
	data = f.read()

configurationData = {
  "id": "1234567-1234567894567878241-12456", # Must be unique
  "name": "Quickstart example",
  "parameters": ["method","classifier","num_layers"],
  "measurements": ["balanced_accuracy"],
  "data": data,
}
output = "index.html"

export(configurationData, output)
