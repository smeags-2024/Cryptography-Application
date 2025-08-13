#include "gui/encryption_dialog.h"
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>

namespace CryptoApp {

EncryptionDialog::EncryptionDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Encrypt File");
    setMinimumSize(500, 400);
    setupUI();
    connectSignals();
}

EncryptionDialog::~EncryptionDialog() {}

void EncryptionDialog::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    
    // Algorithm selection
    QGroupBox* algorithmGroup = new QGroupBox("Encryption Algorithm");
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
    
    fileLayout->addWidget(new QLabel("Input File:"), 0, 0);
    fileLayout->addWidget(inputFileEdit, 0, 1);
    fileLayout->addWidget(browseInputBtn, 0, 2);
    fileLayout->addWidget(new QLabel("Output File:"), 1, 0);
    fileLayout->addWidget(outputFileEdit, 1, 1);
    fileLayout->addWidget(browseOutputBtn, 1, 2);
    
    mainLayout->addWidget(fileGroup);
    
    // Key management
    QGroupBox* keyGroup = new QGroupBox("Encryption Key");
    QHBoxLayout* keyLayout = new QHBoxLayout(keyGroup);
    
    keyEdit = new QLineEdit();
    keyEdit->setEchoMode(QLineEdit::Password);
    generateKeyBtn = new QPushButton("Generate Key");
    
    keyLayout->addWidget(new QLabel("Key:"));
    keyLayout->addWidget(keyEdit);
    keyLayout->addWidget(generateKeyBtn);
    
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
    encryptBtn = new QPushButton("Encrypt");
    cancelBtn = new QPushButton("Cancel");
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(encryptBtn);
    buttonLayout->addWidget(cancelBtn);
    
    mainLayout->addLayout(buttonLayout);
}

void EncryptionDialog::connectSignals() {
    connect(browseInputBtn, &QPushButton::clicked, this, &EncryptionDialog::onBrowseInputFile);
    connect(browseOutputBtn, &QPushButton::clicked, this, &EncryptionDialog::onBrowseOutputFile);
    connect(generateKeyBtn, &QPushButton::clicked, this, &EncryptionDialog::onGenerateKey);
    connect(encryptBtn, &QPushButton::clicked, this, &EncryptionDialog::onEncrypt);
    connect(cancelBtn, &QPushButton::clicked, this, &EncryptionDialog::onCancel);
    connect(algorithmCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &EncryptionDialog::onAlgorithmChanged);
}

void EncryptionDialog::onBrowseInputFile() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select File to Encrypt");
    if (!fileName.isEmpty()) {
        inputFileEdit->setText(fileName);
        if (outputFileEdit->text().isEmpty()) {
            outputFileEdit->setText(fileName + ".enc");
        }
    }
}

void EncryptionDialog::onBrowseOutputFile() {
    QString fileName = QFileDialog::getSaveFileName(this, "Save Encrypted File");
    if (!fileName.isEmpty()) {
        outputFileEdit->setText(fileName);
    }
}

void EncryptionDialog::onGenerateKey() {
    // This would integrate with the key generator
    logArea->append("Key generated (implementation needed)");
}

void EncryptionDialog::onEncrypt() {
    if (inputFileEdit->text().isEmpty() || outputFileEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select input and output files.");
        return;
    }
    
    emit encryptionRequested(getInputFile(), getOutputFile(), getKey(), getAlgorithm());
}

void EncryptionDialog::onCancel() {
    reject();
}

void EncryptionDialog::onAlgorithmChanged() {
    // Update UI based on selected algorithm
}

// Getters and setters
void EncryptionDialog::setAlgorithm(EncryptionAlgorithm algorithm) {
    algorithmCombo->setCurrentIndex(static_cast<int>(algorithm));
}

void EncryptionDialog::setInputFile(const QString& filePath) {
    inputFileEdit->setText(filePath);
}

void EncryptionDialog::setOutputFile(const QString& filePath) {
    outputFileEdit->setText(filePath);
}

void EncryptionDialog::setKey(const QString& key) {
    keyEdit->setText(key);
}

QString EncryptionDialog::getInputFile() const {
    return inputFileEdit->text();
}

QString EncryptionDialog::getOutputFile() const {
    return outputFileEdit->text();
}

QString EncryptionDialog::getKey() const {
    return keyEdit->text();
}

EncryptionAlgorithm EncryptionDialog::getAlgorithm() const {
    return static_cast<EncryptionAlgorithm>(algorithmCombo->currentIndex());
}

} // namespace CryptoApp
