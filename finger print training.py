import tensorflow as tf
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from tensorflow.keras.applications import MobileNetV2
from tensorflow.keras.models import Model
from tensorflow.keras.layers import GlobalAveragePooling2D, Dense, Dropout
from tensorflow.keras.optimizers import Adam

# Enable eager execution for debugging
tf.config.run_functions_eagerly(True)

# Paths and parameters
data_dir = 'fingerprints'  # Replace with your dataset path
IMG_HEIGHT = 224
IMG_WIDTH = 224
BATCH_SIZE = 4

# Data augmentation
data_gen = ImageDataGenerator(rescale=1.0/255, validation_split=0.2)
train_data = data_gen.flow_from_directory(data_dir, target_size=(IMG_HEIGHT, IMG_WIDTH),
                                          batch_size=BATCH_SIZE, class_mode='binary', subset='training')
val_data = data_gen.flow_from_directory(data_dir, target_size=(IMG_HEIGHT, IMG_WIDTH),
                                        batch_size=BATCH_SIZE, class_mode='binary', subset='validation')

# Debugging the data generator
for images, labels in train_data:
    print(images.shape, labels.shape)
    break

# Load pre-trained MobileNetV2
base_model = MobileNetV2(input_shape=(IMG_HEIGHT, IMG_WIDTH, 3), include_top=False, weights='imagenet')
base_model.trainable = False

# Add custom layers
x = GlobalAveragePooling2D()(base_model.output)
x = Dense(128, activation='relu')(x)
x = Dropout(0.3)(x)
output = Dense(1, activation='sigmoid')(x)
model = Model(inputs=base_model.input, outputs=output)

# Compile model
model.compile(optimizer=Adam(learning_rate=0.0001),
              loss='binary_crossentropy',
              metrics=['accuracy'],
              run_eagerly=True)

# Train model
steps_per_epoch = max(1, train_data.samples // BATCH_SIZE)
validation_steps = max(1, val_data.samples // BATCH_SIZE)

history = model.fit(train_data, validation_data=val_data,
                    epochs=10,
                    steps_per_epoch=steps_per_epoch,
                    validation_steps=validation_steps)

# Save model
model.save('authorized_unauthorized_model.h5')
print("Model saved as 'authorized_unauthorized_model.h5'")
