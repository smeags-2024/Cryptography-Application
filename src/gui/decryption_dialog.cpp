#include "gui/decryption_dialog.h"
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>

namespace CryptoApp {

DecryptionDialog::DecryptionDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Decrypt File");
    setMinimumSize(500, 400);
    setupUI();
    connectSignals();
}

DecryptionDialog::~DecryptionDialog() {}

void DecryptionDialog::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    
    // Algorithm selection
    QGroupBox* algorithmGroup = new QGroupBox("Decryption Algorithm");
    QHBoxLayout* algorithmLayout = new QHBoxLayout(algorithmGroup);
    
    algorithmCombo = new QComboBox();
    algorithmCombo->addItems({"AES-256", "RSA-2048", "Blowfish"});
    algorithmLayout->addWidget(new QLabel("Algorithm:"));
    algorithmLayout->addWidget(algorithmCombo);
    
    mainLayout->addWidget(algorithmGroup);
    
    // File selection
    QGroupBox* fileGroup = new QGroupBox("File Selection");
    QGridLayout* fileLayout = new QGridLayout(fileGroup);
    
    inputFileEdit = new QLineEdit();
    browseInputBtn = new QPushButton("Browse...");
    outputFileEdit = new QLineEdit();
    browseOutputBtn = new QPushButton("Browse...");
    
    fileLayout->addWidget(new QLabel("Encrypted File:"), 0, 0);
    fileLayout->addWidget(inputFileEdit, 0, 1);
    fileLayout->addWidget(browseInputBtn, 0, 2);
    fileLayout->addWidget(new QLabel("Output File:"), 1, 0);
    fileLayout->addWidget(outputFileEdit, 1, 1);
    fileLayout->addWidget(browseOutputBtn, 1, 2);
    
    mainLayout->addWidget(fileGroup);
    
    // Key management
    QGroupBox* keyGroup = new QGroupBox("Decryption Key");
    QHBoxLayout* keyLayout = new QHBoxLayout(keyGroup);
    
    keyEdit = new QLineEdit();
    keyEdit->setEchoMode(QLineEdit::Password);
    loadKeyBtn = new QPushButton("Load Key");
    
    keyLayout->addWidget(new QLabel("Key:"));
    keyLayout->addWidget(keyEdit);
    keyLayout->addWidget(loadKeyBtn);
    
    mainLayout->addWidget(keyGroup);
    
    // Log area
    logArea = new QTextEdit();
    logArea->setMaximumHeight(100);
    logArea->setReadOnly(true);
    mainLayout->addWidget(logArea);
    
    // Progress and status
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    statusLabel = new QLabel("Ready");
    
    mainLayout->addWidget(progressBar);
    mainLayout->addWidget(statusLabel);
    
    // Buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    decryptBtn = new QPushButton("Decrypt");
    cancelBtn = new QPushButton("Cancel");
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(decryptBtn);
    buttonLayout->addWidget(cancelBtn);
    
    mainLayout->addLayout(buttonLayout);
}

void DecryptionDialog::connectSignals() {
    connect(browseInputBtn, &QPushButton::clicked, this, &DecryptionDialog::onBrowseInputFile);
    connect(browseOutputBtn, &QPushButton::clicked, this, &DecryptionDialog::onBrowseOutputFile);
    connect(loadKeyBtn, &QPushButton::clicked, this, &DecryptionDialog::onLoadKey);
    connect(decryptBtn, &QPushButton::clicked, this, &DecryptionDialog::onDecrypt);
    connect(cancelBtn, &QPushButton::clicked, this, &DecryptionDialog::onCancel);
    connect(algorithmCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &DecryptionDialog::onAlgorithmChanged);
}

void DecryptionDialog::onBrowseInputFile() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select Encrypted File");
    if (!fileName.isEmpty()) {
        inputFileEdit->setText(fileName);
        if (outputFileEdit->text().isEmpty()) {
            QString baseName = fileName;
            if (baseName.endsWith(".enc")) {
                baseName.chop(4); // Remove .enc extension
            }
            outputFileEdit->setText(baseName + "_decrypted");
        }
    }
}

void DecryptionDialog::onBrowseOutputFile() {
    QString fileName = QFileDialog::getSaveFileName(this, "Save Decrypted File");
    if (!fileName.isEmpty()) {
        outputFileEdit->setText(fileName);
    }
}

void DecryptionDialog::onLoadKey() {
    QString fileName = QFileDialog::getOpenFileName(this, "Load Key File");
    if (!fileName.isEmpty()) {
        logArea->append("Key loaded from: " + fileName);
        // Implementation would load the key from file
    }
}

void DecryptionDialog::onDecrypt() {
    if (inputFileEdit->text().isEmpty() || outputFileEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select input and output files.");
        return;
    }
    
    if (keyEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please provide the decryption key.");
        return;
    }
    
    emit decryptionRequested(getInputFile(), getOutputFile(), getKey(), getAlgorithm());
}

void DecryptionDialog::onCancel() {
    reject();
}

void DecryptionDialog::onAlgorithmChanged() {
    // Update UI based on selected algorithm
}

// Getters and setters
void DecryptionDialog::setAlgorithm(EncryptionAlgorithm algorithm) {
    algorithmCombo->setCurrentIndex(static_cast<int>(algorithm));
}

void DecryptionDialog::setInputFile(const QString& filePath) {
    inputFileEdit->setText(filePath);
}

void DecryptionDialog::setOutputFile(const QString& filePath) {
    outputFileEdit->setText(filePath);
}

void DecryptionDialog::setKey(const QString& key) {
    keyEdit->setText(key);
}

QString DecryptionDialog::getInputFile() const {
    return inputFileEdit->text();
}

QString DecryptionDialog::getOutputFile() const {
    return outputFileEdit->text();
}

QString DecryptionDialog::getKey() const {
    return keyEdit->text();
}

EncryptionAlgorithm DecryptionDialog::getAlgorithm() const {
    return static_cast<EncryptionAlgorithm>(algorithmCombo->currentIndex());
}

} // namespace CryptoApp
