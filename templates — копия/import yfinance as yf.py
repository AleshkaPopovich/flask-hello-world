import yfinance as yf
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_absolute_percentage_error, mean_squared_error, mean_absolute_error
from keras.models import Sequential
from keras.layers import LSTM, Dense
import matplotlib.pyplot as plt




# Load the data
ticker = 'symbol'  # Example ticker symbol
data = yf.download(ticker, start="2020-01-01", end="2023-01-01")




# Preprocess the data
data['Date'] = data.index
data = data[['Date', 'Close']]




# Normalize the data
scaler = MinMaxScaler(feature_range=(0, 1))
scaled_data = scaler.fit_transform(data['Close'].values.reshape(-1, 1))




# Create the sequences for the LSTM
def create_sequences(data, seq_length):
   sequences = []
   labels = []
   for i in range(len(data) - seq_length):
       seq = data[i:i + seq_length]
       label = data[i + seq_length]
       sequences.append(seq)
       labels.append(label)
   return np.array(sequences), np.array(labels)




seq_length = 60
X, y = create_sequences(scaled_data, seq_length)




# Split the data into training and testing sets (80% train, 20% test)
train_size = int(len(X) * 0.8)
X_train, X_test = X[:train_size], X[train_size:]
y_train, y_test = y[:train_size], y[train_size:]




# Reshape for LSTM layer
X_train = np.reshape(X_train, (X_train.shape[0], X_train.shape[1], 1))
X_test = np.reshape(X_test, (X_test.shape[0], X_test.shape[1], 1))




# Build the LSTM model
model = Sequential()
model.add(LSTM(units=50, return_sequences=True, input_shape=(seq_length, 1)))
model.add(LSTM(units=50, return_sequences=False))
model.add(Dense(units=1))




model.compile(optimizer='adam', loss='mean_squared_error')
model.summary()




# Train the model
model.fit(X_train, y_train, epochs=10, batch_size=32)




# Make predictions
predictions = model.predict(X_test)
predictions = scaler.inverse_transform(predictions)




# Inverse transform y_test
y_test = scaler.inverse_transform(y_test)




# Calculate evaluation metrics
mape = mean_absolute_percentage_error(y_test, predictions)
rmse = np.sqrt(mean_squared_error(y_test, predictions))
mae = mean_absolute_error(y_test, predictions)




print(f"Mean Absolute Percentage Error (MAPE): {mape}")
print(f"Root Mean Squared Error (RMSE): {rmse}")
print(f"Mean Absolute Error (MAE): {mae}")




# Plot the results
plt.figure(figsize=(14,5))
plt.plot(data['Date'][-len(y_test):], y_test, color='blue', label='Actual Stock Price')
plt.plot(data['Date'][-len(predictions):], predictions, color='red', label='Predicted Stock Price')
plt.title(f'{ticker} Stock Price Prediction')
plt.xlabel('Date')
plt.ylabel('Stock Price')
plt.legend()
plt.show()
