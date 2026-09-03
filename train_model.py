import pandas as pd

data = pd.read_csv(r"D:\Phishing_Detection_Project\dataset.csv")

print(data.head())
print(data.columns)
data["label"] = data["label"].map({
    "ham": 0,
    "spam": 1
})

print(data.head())