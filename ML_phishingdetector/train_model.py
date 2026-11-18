# import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.feature_extraction.text import TfidfVectorizer
# from sklearn.naive_bayes import MultinomialNB
# import pickle

# # 1. Load dataset
# data = pd.read_csv("dataset.csv")

# # 2. Split input and output
# X = data["text"]
# y = data["label"]

# # 3. Convert text → numbers
# vectorizer = TfidfVectorizer(
#     ngram_range=(1, 2),
#     stop_words='english'
# )
# X_vec = vectorizer.fit_transform(X)

# # 4. Split data into training & testing
# X_train, X_test, y_train, y_test = train_test_split(
#     X_vec, y, test_size=0.2, random_state=42
# )

# # 5. Train ML model
# model = MultinomialNB()
# model.fit(X_train, y_train)

# # 6. Save model and vectorizer
# pickle.dump(model, open("model.pkl", "wb"))
# pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

# print("✅ Model trained successfully!")



import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score

# Load dataset
data = pd.read_csv("dataset.csv")

X = data["text"]
y = data["label"]

# Better vectorizer
vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1,3),
    max_features=10000,
    min_df=2
)

X_vec = vectorizer.fit_transform(X)

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y, test_size=0.2, random_state=42
)

# ⭐ Better model (IMPORTANT CHANGE)
model = LinearSVC()
model.fit(X_train, y_train)

# Accuracy check
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print("Model Accuracy:", acc * 100, "%")

# Save model
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model trained successfully!")