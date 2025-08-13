#include "gui/signature_dialog.h"
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>

namespace CryptoApp {

SignatureDialog::SignatureDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Digital Signature");
    setMinimumSize(600, 500);
    setupUI();
    connectSignals();
}

SignatureDialog::~SignatureDialog() {}

void SignatureDialog::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    
    // Hash algorithm selection
    QGroupBox* algorithmGroup = new QGroupBox("Hash Algorithm");
    QHBoxLayout* algorithmLayout = new QHBoxLayout(algorithmGroup);
    
    hashAlgorithmCombo = new QComboBox();
    hashAlgorithmCombo->addItems({"SHA-256", "MD5"});
    algorithmLayout->addWidget(new QLabel("Algorithm:"));
    algorithmLayout->addWidget(hashAlgorithmCombo);
    algorithmLayout->addStretch();
    
    generateKeyPairBtn = new QPushButton("Generate Key Pair");
    algorithmLayout->addWidget(generateKeyPairBtn);
    
    mainLayout->addWidget(algorithmGroup);
    
    // Tab widget for sign/verify
    tabWidget = new QTabWidget();
    setupSignTab();
    setupVerifyTab();
    
    mainLayout->addWidget(tabWidget);
    
    // Result area
    QGroupBox* resultGroup = new QGroupBox("Results");
    QVBoxLayout* resultLayout = new QVBoxLayout(resultGroup);
    
    resultArea = new QTextEdit();
    resultArea->setReadOnly(true);
    resultArea->setMaximumHeight(150);
    resultLayout->addWidget(resultArea);
    
    mainLayout->addWidget(resultGroup);
    
    // Progress and status
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    statusLabel = new QLabel("Ready");
    
    mainLayout->addWidget(progressBar);
    mainLayout->addWidget(statusLabel);
    
    // Close button
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    closeBtn = new QPushButton("Close");
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeBtn);
    
    mainLayout->addLayout(buttonLayout);
}

void SignatureDialog::setupSignTab() {
    signTab = new QWidget();
    tabWidget->addTab(signTab, "Sign File");
    
    QVBoxLayout* signLayout = new QVBoxLayout(signTab);
    
    // File selection
    QGroupBox* fileGroup = new QGroupBox("File Selection");
    QGridLayout* fileLayout = new QGridLayout(fileGroup);
    
    signFileEdit = new QLineEdit();
    browseSignFileBtn = new QPushButton("Browse...");
    signatureFileEdit = new QLineEdit();
    browseSignatureFileBtn = new QPushButton("Browse...");
    
    fileLayout->addWidget(new QLabel("File to Sign:"), 0, 0);
    fileLayout->addWidget(signFileEdit, 0, 1);
    fileLayout->addWidget(browseSignFileBtn, 0, 2);
    fileLayout->addWidget(new QLabel("Signature File:"), 1, 0);
    fileLayout->addWidget(signatureFileEdit, 1, 1);
    fileLayout->addWidget(browseSignatureFileBtn, 1, 2);
    
    signLayout->addWidget(fileGroup);
    
    // Private key
    QGroupBox* keyGroup = new QGroupBox("Private Key");
    QVBoxLayout* keyLayout = new QVBoxLayout(keyGroup);
    
    QHBoxLayout* keyButtonLayout = new QHBoxLayout();
    loadPrivateKeyBtn = new QPushButton("Load Private Key");
    keyButtonLayout->addWidget(loadPrivateKeyBtn);
    keyButtonLayout->addStretch();
    
    privateKeyEdit = new QTextEdit();
    privateKeyEdit->setMaximumHeight(100);
    privateKeyEdit->setPlaceholderText("Private key will appear here...");
    
    keyLayout->addLayout(keyButtonLayout);
    keyLayout->addWidget(privateKeyEdit);
    
    signLayout->addWidget(keyGroup);
    
    // Sign button
    QHBoxLayout* signButtonLayout = new QHBoxLayout();
    signBtn = new QPushButton("Sign File");
    signButtonLayout->addStretch();
    signButtonLayout->addWidget(signBtn);
    
    signLayout->addLayout(signButtonLayout);
}

void SignatureDialog::setupVerifyTab() {
    verifyTab = new QWidget();
    tabWidget->addTab(verifyTab, "Verify Signature");
    
    QVBoxLayout* verifyLayout = new QVBoxLayout(verifyTab);
    
    // File selection
    QGroupBox* fileGroup = new QGroupBox("File Selection");
    QGridLayout* fileLayout = new QGridLayout(fileGroup);
    
    verifyFileEdit = new QLineEdit();
    browseVerifyFileBtn = new QPushButton("Browse...");
    verifySignatureFileEdit = new QLineEdit();
    browseVerifySignatureFileBtn = new QPushButton("Browse...");
    
    fileLayout->addWidget(new QLabel("Original File:"), 0, 0);
    fileLayout->addWidget(verifyFileEdit, 0, 1);
    fileLayout->addWidget(browseVerifyFileBtn, 0, 2);
    fileLayout->addWidget(new QLabel("Signature File:"), 1, 0);
    fileLayout->addWidget(verifySignatureFileEdit, 1, 1);
    fileLayout->addWidget(browseVerifySignatureFileBtn, 1, 2);
    
    verifyLayout->addWidget(fileGroup);
    
    // Public key
    QGroupBox* keyGroup = new QGroupBox("Public Key");
    QVBoxLayout* keyLayout = new QVBoxLayout(keyGroup);
    
    QHBoxLayout* keyButtonLayout = new QHBoxLayout();
    loadPublicKeyBtn = new QPushButton("Load Public Key");
    keyButtonLayout->addWidget(loadPublicKeyBtn);
    keyButtonLayout->addStretch();
    
    publicKeyEdit = new QTextEdit();
    publicKeyEdit->setMaximumHeight(100);
    publicKeyEdit->setPlaceholderText("Public key will appear here...");
    
    keyLayout->addLayout(keyButtonLayout);
    keyLayout->addWidget(publicKeyEdit);
    
    verifyLayout->addWidget(keyGroup);
    
    // Verify button
    QHBoxLayout* verifyButtonLayout = new QHBoxLayout();
    verifyBtn = new QPushButton("Verify Signature");
    verifyButtonLayout->addStretch();
    verifyButtonLayout->addWidget(verifyBtn);
    
    verifyLayout->addLayout(verifyButtonLayout);
}

void SignatureDialog::connectSignals() {
    // Sign tab signals
    connect(browseSignFileBtn, &QPushButton::clicked, this, &SignatureDialog::onBrowseSignFile);
    connect(browseSignatureFileBtn, &QPushButton::clicked, this, &SignatureDialog::onBrowseSignatureFile);
    connect(loadPrivateKeyBtn, &QPushButton::clicked, this, &SignatureDialog::onLoadPrivateKey);
    connect(signBtn, &QPushButton::clicked, this, &SignatureDialog::onSign);
    
    // Verify tab signals
    connect(browseVerifyFileBtn, &QPushButton::clicked, this, &SignatureDialog::onBrowseVerifyFile);
    connect(browseVerifySignatureFileBtn, &QPushButton::clicked, this, &SignatureDialog::onBrowseVerifySignatureFile);
    connect(loadPublicKeyBtn, &QPushButton::clicked, this, &SignatureDialog::onLoadPublicKey);
    connect(verifyBtn, &QPushButton::clicked, this, &SignatureDialog::onVerify);
    
    // Common signals
    connect(generateKeyPairBtn, &QPushButton::clicked, this, &SignatureDialog::onGenerateKeyPair);
    connect(closeBtn, &QPushButton::clicked, this, &SignatureDialog::onClose);
    connect(hashAlgorithmCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SignatureDialog::onHashAlgorithmChanged);
}

void SignatureDialog::onBrowseSignFile() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select File to Sign");
    if (!fileName.isEmpty()) {
        signFileEdit->setText(fileName);
        if (signatureFileEdit->text().isEmpty()) {
            signatureFileEdit->setText(fileName + ".sig");
        }
    }
}

void SignatureDialog::onBrowseSignatureFile() {
    QString fileName = QFileDialog::getSaveFileName(this, "Save Signature File", "", "Signature Files (*.sig)");
    if (!fileName.isEmpty()) {
        signatureFileEdit->setText(fileName);
    }
}

void SignatureDialog::onLoadPrivateKey() {
    QString fileName = QFileDialog::getOpenFileName(this, "Load Private Key", "", "Key Files (*.pem *.key)");
    if (!fileName.isEmpty()) {
        resultArea->append("Private key loaded from: " + fileName);
        // Implementation would load the actual key
    }
}

void SignatureDialog::onSign() {
    if (signFileEdit->text().isEmpty() || signatureFileEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select file and signature output.");
        return;
    }
    
    if (privateKeyEdit->toPlainText().isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please provide a private key.");
        return;
    }
    
    emit signRequested(signFileEdit->text(), signatureFileEdit->text(), 
                      privateKeyEdit->toPlainText(), getHashAlgorithm());
}

void SignatureDialog::onBrowseVerifyFile() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select Original File");
    if (!fileName.isEmpty()) {
        verifyFileEdit->setText(fileName);
    }
}

void SignatureDialog::onBrowseVerifySignatureFile() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select Signature File", "", "Signature Files (*.sig)");
    if (!fileName.isEmpty()) {
        verifySignatureFileEdit->setText(fileName);
    }
}

void SignatureDialog::onLoadPublicKey() {
    QString fileName = QFileDialog::getOpenFileName(this, "Load Public Key", "", "Key Files (*.pem *.pub)");
    if (!fileName.isEmpty()) {
        resultArea->append("Public key loaded from: " + fileName);
        // Implementation would load the actual key
    }
}

void SignatureDialog::onVerify() {
    if (verifyFileEdit->text().isEmpty() || verifySignatureFileEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select file and signature file.");
        return;
    }
    
    if (publicKeyEdit->toPlainText().isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please provide a public key.");
        return;
    }
    
    emit verifyRequested(verifyFileEdit->text(), verifySignatureFileEdit->text(), 
                        publicKeyEdit->toPlainText(), getHashAlgorithm());
}

void SignatureDialog::onGenerateKeyPair() {
    resultArea->append("Generating RSA key pair...");
    // Implementation would generate key pair and populate the text areas
}

void SignatureDialog::onClose() {
    accept();
}

void SignatureDialog::onHashAlgorithmChanged() {
    // Update UI based on selected hash algorithm
}

void SignatureDialog::setHashAlgorithm(HashAlgorithm algorithm) {
    int index = (algorithm == HashAlgorithm::SHA256) ? 0 : 1;
    hashAlgorithmCombo->setCurrentIndex(index);
}

HashAlgorithm SignatureDialog::getHashAlgorithm() const {
    return (hashAlgorithmCombo->currentIndex() == 0) ? HashAlgorithm::SHA256 : HashAlgorithm::MD5;
}

} // namespace CryptoApp
