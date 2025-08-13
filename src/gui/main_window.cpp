#include "gui/main_window.h"
#include "cryptography/aes_crypto.h"
#include "cryptography/rsa_crypto.h"
#include "cryptography/blowfish_crypto.h"
#include "cryptography/hash_functions.h"
#include "cryptography/digital_signature.h"
#include "storage/secure_storage.h"

#include <QtWidgets/QApplication>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QSplitter>
#include <QtCore/QDir>
#include <QtCore/QDateTime>

namespace CryptoApp {

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    // Initialize crypto components
    aes = new AESCrypto();
    rsa = new RSACrypto();
    blowfish = new BlowfishCrypto();
    hashFunc = new HashFunctions();
    digitalSig = new DigitalSignature();
    secureStorage = new SecureStorage(QDir::homePath().toStdString() + "/.cryptoapp");
    
    // Set window properties
    setWindowTitle("Cryptography Application");
    setMinimumSize(800, 600);
    resize(1200, 800);
    
    // Create UI
    centralTabs = new QTabWidget(this);
    setCentralWidget(centralTabs);
    
    createActions();
    createMenus();
    createEncryptionTab();
    createHashTab();
    createSignatureTab();
    createStorageTab();
    createSettingsTab();
    setupStatusBar();
    
    logMessage("Cryptography Application initialized successfully");
}

MainWindow::~MainWindow() {
    delete aes;
    delete rsa;
    delete blowfish;
    delete hashFunc;
    delete digitalSig;
    delete secureStorage;
}

void MainWindow::createActions() {
    exitAction = new QAction("&Exit", this);
    exitAction->setShortcuts(QKeySequence::Quit);
    exitAction->setStatusTip("Exit the application");
    connect(exitAction, &QAction::triggered, this, &MainWindow::onExit);
    
    aboutAction = new QAction("&About", this);
    aboutAction->setStatusTip("Show the application's About box");
    connect(aboutAction, &QAction::triggered, this, &MainWindow::onAbout);
}

void MainWindow::createMenus() {
    m_menuBar = this->menuBar();
    
    fileMenu = m_menuBar->addMenu("&File");
    fileMenu->addSeparator();
    fileMenu->addAction(exitAction);
    
    toolsMenu = m_menuBar->addMenu("&Tools");
    
    helpMenu = m_menuBar->addMenu("&Help");
    helpMenu->addAction(aboutAction);
}

void MainWindow::createEncryptionTab() {
    encryptionTab = new QWidget();
    centralTabs->addTab(encryptionTab, "Encryption");
    
    QVBoxLayout* mainLayout = new QVBoxLayout(encryptionTab);
    
    // Algorithm selection group
    QGroupBox* algorithmGroup = new QGroupBox("Encryption Algorithm");
    QHBoxLayout* algorithmLayout = new QHBoxLayout(algorithmGroup);
    
    algorithmCombo = new QComboBox();
    algorithmCombo->addItems({"AES-256", "RSA-2048", "Blowfish"});
    connect(algorithmCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onAlgorithmChanged);
    
    algorithmLayout->addWidget(new QLabel("Algorithm:"));
    algorithmLayout->addWidget(algorithmCombo);
    algorithmLayout->addStretch();
    
    mainLayout->addWidget(algorithmGroup);
    
    // Operations group
    QGroupBox* operationsGroup = new QGroupBox("Operations");
    QHBoxLayout* operationsLayout = new QHBoxLayout(operationsGroup);
    
    encryptFileBtn = new QPushButton("Encrypt File");
    decryptFileBtn = new QPushButton("Decrypt File");
    generateKeyBtn = new QPushButton("Generate Key");
    
    connect(encryptFileBtn, &QPushButton::clicked, this, &MainWindow::onEncryptFile);
    connect(decryptFileBtn, &QPushButton::clicked, this, &MainWindow::onDecryptFile);
    connect(generateKeyBtn, &QPushButton::clicked, this, &MainWindow::onGenerateKey);
    
    operationsLayout->addWidget(encryptFileBtn);
    operationsLayout->addWidget(decryptFileBtn);
    operationsLayout->addWidget(generateKeyBtn);
    operationsLayout->addStretch();
    
    mainLayout->addWidget(operationsGroup);
    
    // Key display area
    QGroupBox* keyGroup = new QGroupBox("Key Information");
    QVBoxLayout* keyLayout = new QVBoxLayout(keyGroup);
    
    keyDisplayArea = new QTextEdit();
    keyDisplayArea->setMaximumHeight(150);
    keyDisplayArea->setPlaceholderText("Generated keys will appear here...");
    
    keyLayout->addWidget(keyDisplayArea);
    mainLayout->addWidget(keyGroup);
    
    // Log area
    QGroupBox* logGroup = new QGroupBox("Operation Log");
    QVBoxLayout* logLayout = new QVBoxLayout(logGroup);
    
    logArea = new QTextEdit();
    logArea->setReadOnly(true);
    logArea->setPlaceholderText("Operation results will appear here...");
    
    logLayout->addWidget(logArea);
    mainLayout->addWidget(logGroup);
}

void MainWindow::createHashTab() {
    hashTab = new QWidget();
    centralTabs->addTab(hashTab, "Hash Functions");
    
    QVBoxLayout* mainLayout = new QVBoxLayout(hashTab);
    
    // Hash algorithm selection
    QGroupBox* algorithmGroup = new QGroupBox("Hash Algorithm");
    QHBoxLayout* algorithmLayout = new QHBoxLayout(algorithmGroup);
    
    hashAlgorithmCombo = new QComboBox();
    hashAlgorithmCombo->addItems({"SHA-256", "MD5"});
    connect(hashAlgorithmCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::onHashAlgorithmChanged);
    
    algorithmLayout->addWidget(new QLabel("Algorithm:"));
    algorithmLayout->addWidget(hashAlgorithmCombo);
    algorithmLayout->addStretch();
    
    mainLayout->addWidget(algorithmGroup);
    
    // Operations
    QGroupBox* operationsGroup = new QGroupBox("Operations");
    QHBoxLayout* operationsLayout = new QHBoxLayout(operationsGroup);
    
    calculateHashBtn = new QPushButton("Calculate Hash");
    verifyHashBtn = new QPushButton("Verify Hash");
    
    connect(calculateHashBtn, &QPushButton::clicked, this, &MainWindow::onCalculateHash);
    connect(verifyHashBtn, &QPushButton::clicked, this, &MainWindow::onVerifyHash);
    
    operationsLayout->addWidget(calculateHashBtn);
    operationsLayout->addWidget(verifyHashBtn);
    operationsLayout->addStretch();
    
    mainLayout->addWidget(operationsGroup);
    
    // Results area
    QGroupBox* resultGroup = new QGroupBox("Hash Results");
    QVBoxLayout* resultLayout = new QVBoxLayout(resultGroup);
    
    hashResultArea = new QTextEdit();
    hashResultArea->setReadOnly(true);
    hashResultArea->setPlaceholderText("Hash calculation results will appear here...");
    
    resultLayout->addWidget(hashResultArea);
    mainLayout->addWidget(resultGroup);
}

void MainWindow::createSignatureTab() {
    signatureTab = new QWidget();
    centralTabs->addTab(signatureTab, "Digital Signatures");
    
    QVBoxLayout* mainLayout = new QVBoxLayout(signatureTab);
    
    // Operations
    QGroupBox* operationsGroup = new QGroupBox("Operations");
    QHBoxLayout* operationsLayout = new QHBoxLayout(operationsGroup);
    
    generateKeyPairBtn = new QPushButton("Generate Key Pair");
    signFileBtn = new QPushButton("Sign File");
    verifySignatureBtn = new QPushButton("Verify Signature");
    
    connect(generateKeyPairBtn, &QPushButton::clicked, this, &MainWindow::onGenerateKeyPair);
    connect(signFileBtn, &QPushButton::clicked, this, &MainWindow::onSignFile);
    connect(verifySignatureBtn, &QPushButton::clicked, this, &MainWindow::onVerifySignature);
    
    operationsLayout->addWidget(generateKeyPairBtn);
    operationsLayout->addWidget(signFileBtn);
    operationsLayout->addWidget(verifySignatureBtn);
    operationsLayout->addStretch();
    
    mainLayout->addWidget(operationsGroup);
    
    // Key areas
    QSplitter* keySplitter = new QSplitter(Qt::Horizontal);
    
    QGroupBox* publicKeyGroup = new QGroupBox("Public Key");
    QVBoxLayout* publicKeyLayout = new QVBoxLayout(publicKeyGroup);
    publicKeyArea = new QTextEdit();
    publicKeyArea->setPlaceholderText("Public key will appear here...");
    publicKeyLayout->addWidget(publicKeyArea);
    
    QGroupBox* privateKeyGroup = new QGroupBox("Private Key");
    QVBoxLayout* privateKeyLayout = new QVBoxLayout(privateKeyGroup);
    privateKeyArea = new QTextEdit();
    privateKeyArea->setPlaceholderText("Private key will appear here...");
    privateKeyLayout->addWidget(privateKeyArea);
    
    keySplitter->addWidget(publicKeyGroup);
    keySplitter->addWidget(privateKeyGroup);
    
    mainLayout->addWidget(keySplitter);
    
    // Results area
    QGroupBox* resultGroup = new QGroupBox("Signature Results");
    QVBoxLayout* resultLayout = new QVBoxLayout(resultGroup);
    
    signatureResultArea = new QTextEdit();
    signatureResultArea->setReadOnly(true);
    signatureResultArea->setPlaceholderText("Signature operation results will appear here...");
    
    resultLayout->addWidget(signatureResultArea);
    mainLayout->addWidget(resultGroup);
}

void MainWindow::createStorageTab() {
    storageTab = new QWidget();
    centralTabs->addTab(storageTab, "Secure Storage");
    
    QVBoxLayout* mainLayout = new QVBoxLayout(storageTab);
    
    // Operations
    QGroupBox* operationsGroup = new QGroupBox("Storage Operations");
    QGridLayout* operationsLayout = new QGridLayout(operationsGroup);
    
    initStorageBtn = new QPushButton("Initialize Storage");
    unlockStorageBtn = new QPushButton("Unlock Storage");
    storeFileBtn = new QPushButton("Store File");
    retrieveFileBtn = new QPushButton("Retrieve File");
    listFilesBtn = new QPushButton("List Files");
    
    connect(initStorageBtn, &QPushButton::clicked, this, &MainWindow::onInitStorage);
    connect(unlockStorageBtn, &QPushButton::clicked, this, &MainWindow::onUnlockStorage);
    connect(storeFileBtn, &QPushButton::clicked, this, &MainWindow::onStoreFile);
    connect(retrieveFileBtn, &QPushButton::clicked, this, &MainWindow::onRetrieveFile);
    connect(listFilesBtn, &QPushButton::clicked, this, &MainWindow::onListFiles);
    
    operationsLayout->addWidget(initStorageBtn, 0, 0);
    operationsLayout->addWidget(unlockStorageBtn, 0, 1);
    operationsLayout->addWidget(storeFileBtn, 1, 0);
    operationsLayout->addWidget(retrieveFileBtn, 1, 1);
    operationsLayout->addWidget(listFilesBtn, 1, 2);
    
    mainLayout->addWidget(operationsGroup);
    
    // Storage log area
    QGroupBox* logGroup = new QGroupBox("Storage Log");
    QVBoxLayout* logLayout = new QVBoxLayout(logGroup);
    
    storageLogArea = new QTextEdit();
    storageLogArea->setReadOnly(true);
    storageLogArea->setPlaceholderText("Storage operation results will appear here...");
    
    logLayout->addWidget(storageLogArea);
    mainLayout->addWidget(logGroup);
}

void MainWindow::createSettingsTab() {
    settingsTab = new QWidget();
    centralTabs->addTab(settingsTab, "Settings");
    
    QVBoxLayout* mainLayout = new QVBoxLayout(settingsTab);
    
    QLabel* settingsLabel = new QLabel("Settings and configuration options will be implemented here.");
    settingsLabel->setAlignment(Qt::AlignCenter);
    
    mainLayout->addWidget(settingsLabel);
    mainLayout->addStretch();
}

void MainWindow::setupStatusBar() {
    m_statusBar = this->statusBar();
    
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    progressBar->setMaximumWidth(200);
    
    m_statusBar->addPermanentWidget(progressBar);
    m_statusBar->showMessage("Ready");
}

void MainWindow::logMessage(const QString& message) {
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    QString logEntry = QString("[%1] %2").arg(timestamp, message);
    
    if (logArea) {
        logArea->append(logEntry);
    }
    
    m_statusBar->showMessage(message, 5000);
}

void MainWindow::updateProgressBar(int value) {
    if (value >= 0 && value <= 100) {
        progressBar->setValue(value);
        progressBar->setVisible(true);
    } else {
        progressBar->setVisible(false);
    }
}

// Slot implementations will be in the next part due to length...

void MainWindow::onEncryptFile() {
    QString inputFile = QFileDialog::getOpenFileName(this, "Select File to Encrypt");
    if (inputFile.isEmpty()) return;
    
    QString outputFile = QFileDialog::getSaveFileName(this, "Save Encrypted File", 
                                                    inputFile + ".enc");
    if (outputFile.isEmpty()) return;
    
    updateProgressBar(10);
    
    try {
        EncryptionAlgorithm algorithm = static_cast<EncryptionAlgorithm>(algorithmCombo->currentIndex());
        OperationResult result;
        
        switch (algorithm) {
            case EncryptionAlgorithm::AES_256: {
                ByteVector key = aes->generateRandomKey();
                result = aes->encryptFile(inputFile.toStdString(), outputFile.toStdString(), key);
                if (result.success) {
                    keyDisplayArea->setText(QString::fromStdString(hashFunc->bytesToHex(key)));
                }
                break;
            }
            case EncryptionAlgorithm::RSA_2048: {
                auto keyPair = rsa->generateKeyPair();
                // For large files, we would typically use hybrid encryption
                QMessageBox::information(this, "Info", "RSA is typically used for small data or key exchange. Consider using AES for file encryption.");
                updateProgressBar(-1);
                return;
            }
            case EncryptionAlgorithm::BLOWFISH: {
                ByteVector key = blowfish->generateRandomKey();
                result = blowfish->encryptFile(inputFile.toStdString(), outputFile.toStdString(), key);
                if (result.success) {
                    keyDisplayArea->setText(QString::fromStdString(hashFunc->bytesToHex(key)));
                }
                break;
            }
        }
        
        updateProgressBar(100);
        
        if (result.success) {
            logMessage("File encrypted successfully: " + outputFile);
            logArea->append(QString::fromStdString(result.message));
        } else {
            QMessageBox::critical(this, "Encryption Error", QString::fromStdString(result.message));
            logMessage("Encryption failed: " + QString::fromStdString(result.message));
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Encryption failed: %1").arg(e.what()));
        logMessage("Encryption error: " + QString(e.what()));
    }
    
    updateProgressBar(-1);
}

void MainWindow::onDecryptFile() {
    QString inputFile = QFileDialog::getOpenFileName(this, "Select Encrypted File");
    if (inputFile.isEmpty()) return;
    
    QString outputFile = QFileDialog::getSaveFileName(this, "Save Decrypted File");
    if (outputFile.isEmpty()) return;
    
    QString keyText = keyDisplayArea->toPlainText().trimmed();
    if (keyText.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please provide the encryption key.");
        return;
    }
    
    updateProgressBar(10);
    
    try {
        EncryptionAlgorithm algorithm = static_cast<EncryptionAlgorithm>(algorithmCombo->currentIndex());
        OperationResult result;
        
        switch (algorithm) {
            case EncryptionAlgorithm::AES_256: {
                ByteVector key = hashFunc->hexToBytes(keyText.toStdString());
                result = aes->decryptFile(inputFile.toStdString(), outputFile.toStdString(), key);
                break;
            }
            case EncryptionAlgorithm::BLOWFISH: {
                ByteVector key = hashFunc->hexToBytes(keyText.toStdString());
                result = blowfish->decryptFile(inputFile.toStdString(), outputFile.toStdString(), key);
                break;
            }
            default:
                QMessageBox::information(this, "Info", "Decryption not implemented for this algorithm in file mode.");
                updateProgressBar(-1);
                return;
        }
        
        updateProgressBar(100);
        
        if (result.success) {
            logMessage("File decrypted successfully: " + outputFile);
            logArea->append(QString::fromStdString(result.message));
        } else {
            QMessageBox::critical(this, "Decryption Error", QString::fromStdString(result.message));
            logMessage("Decryption failed: " + QString::fromStdString(result.message));
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Decryption failed: %1").arg(e.what()));
        logMessage("Decryption error: " + QString(e.what()));
    }
    
    updateProgressBar(-1);
}

void MainWindow::onGenerateKey() {
    EncryptionAlgorithm algorithm = static_cast<EncryptionAlgorithm>(algorithmCombo->currentIndex());
    
    try {
        switch (algorithm) {
            case EncryptionAlgorithm::AES_256: {
                ByteVector key = aes->generateRandomKey();
                keyDisplayArea->setText(QString::fromStdString(hashFunc->bytesToHex(key)));
                logMessage("AES-256 key generated successfully");
                break;
            }
            case EncryptionAlgorithm::RSA_2048: {
                auto keyPair = rsa->generateKeyPair();
                keyDisplayArea->setText("Public Key:\n" + QString::fromStdString(keyPair.first) +
                                      "\n\nPrivate Key:\n" + QString::fromStdString(keyPair.second));
                logMessage("RSA-2048 key pair generated successfully");
                break;
            }
            case EncryptionAlgorithm::BLOWFISH: {
                ByteVector key = blowfish->generateRandomKey();
                keyDisplayArea->setText(QString::fromStdString(hashFunc->bytesToHex(key)));
                logMessage("Blowfish key generated successfully");
                break;
            }
        }
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Key generation failed: %1").arg(e.what()));
        logMessage("Key generation error: " + QString(e.what()));
    }
}

void MainWindow::onCalculateHash() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Hash");
    if (filePath.isEmpty()) return;
    
    HashAlgorithm algorithm = (hashAlgorithmCombo->currentText() == "SHA-256") ? 
                             HashAlgorithm::SHA256 : HashAlgorithm::MD5;
    
    try {
        updateProgressBar(50);
        std::string hash = hashFunc->calculateHashFile(filePath.toStdString(), algorithm);
        updateProgressBar(100);
        
        QString result = QString("File: %1\nAlgorithm: %2\nHash: %3\n\n")
                        .arg(QFileInfo(filePath).fileName())
                        .arg(hashAlgorithmCombo->currentText())
                        .arg(QString::fromStdString(hash));
        
        hashResultArea->append(result);
        logMessage("Hash calculated successfully");
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Hash calculation failed: %1").arg(e.what()));
        logMessage("Hash calculation error: " + QString(e.what()));
    }
    
    updateProgressBar(-1);
}

void MainWindow::onVerifyHash() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Verify");
    if (filePath.isEmpty()) return;
    
    bool ok;
    QString expectedHash = QInputDialog::getText(this, "Hash Verification", 
                                               "Enter expected hash:", 
                                               QLineEdit::Normal, "", &ok);
    if (!ok || expectedHash.isEmpty()) return;
    
    HashAlgorithm algorithm = (hashAlgorithmCombo->currentText() == "SHA-256") ? 
                             HashAlgorithm::SHA256 : HashAlgorithm::MD5;
    
    try {
        updateProgressBar(50);
        bool isValid = hashFunc->verifyHashFile(filePath.toStdString(), 
                                              expectedHash.toStdString(), algorithm);
        updateProgressBar(100);
        
        QString result = QString("File: %1\nExpected Hash: %2\nVerification: %3\n\n")
                        .arg(QFileInfo(filePath).fileName())
                        .arg(expectedHash)
                        .arg(isValid ? "VALID" : "INVALID");
        
        hashResultArea->append(result);
        
        if (isValid) {
            logMessage("Hash verification successful - File is valid");
        } else {
            logMessage("Hash verification failed - File may be corrupted");
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Hash verification failed: %1").arg(e.what()));
        logMessage("Hash verification error: " + QString(e.what()));
    }
    
    updateProgressBar(-1);
}

void MainWindow::onGenerateKeyPair() {
    try {
        updateProgressBar(50);
        auto keyPair = rsa->generateKeyPair();
        updateProgressBar(100);
        
        publicKeyArea->setText(QString::fromStdString(keyPair.first));
        privateKeyArea->setText(QString::fromStdString(keyPair.second));
        
        signatureResultArea->append("RSA key pair generated successfully\n");
        logMessage("RSA key pair generated successfully");
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Key pair generation failed: %1").arg(e.what()));
        logMessage("Key pair generation error: " + QString(e.what()));
    }
    
    updateProgressBar(-1);
}

void MainWindow::onSignFile() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Sign");
    if (filePath.isEmpty()) return;
    
    QString privateKey = privateKeyArea->toPlainText().trimmed();
    if (privateKey.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please provide a private key for signing.");
        return;
    }
    
    QString signatureFile = QFileDialog::getSaveFileName(this, "Save Signature File", 
                                                       filePath + ".sig");
    if (signatureFile.isEmpty()) return;
    
    try {
        updateProgressBar(30);
        auto result = digitalSig->signFile(filePath.toStdString(), 
                                         privateKey.toStdString(), 
                                         signatureFile.toStdString());
        updateProgressBar(100);
        
        if (result.success) {
            QString resultText = QString("File signed successfully\nFile: %1\nSignature: %2\n\n")
                               .arg(QFileInfo(filePath).fileName())
                               .arg(QFileInfo(signatureFile).fileName());
            signatureResultArea->append(resultText);
            logMessage("File signed successfully");
        } else {
            QMessageBox::critical(this, "Signing Error", QString::fromStdString(result.message));
            logMessage("File signing failed: " + QString::fromStdString(result.message));
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("File signing failed: %1").arg(e.what()));
        logMessage("File signing error: " + QString(e.what()));
    }
    
    updateProgressBar(-1);
}

void MainWindow::onVerifySignature() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Verify");
    if (filePath.isEmpty()) return;
    
    QString signatureFile = QFileDialog::getOpenFileName(this, "Select Signature File", 
                                                       "", "Signature Files (*.sig)");
    if (signatureFile.isEmpty()) return;
    
    QString publicKey = publicKeyArea->toPlainText().trimmed();
    if (publicKey.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please provide a public key for verification.");
        return;
    }
    
    try {
        updateProgressBar(30);
        auto result = digitalSig->verifyFileSignature(filePath.toStdString(),
                                                    signatureFile.toStdString(),
                                                    publicKey.toStdString());
        updateProgressBar(100);
        
        QString resultText = QString("Signature Verification\nFile: %1\nSignature: %2\nResult: %3\nInfo: %4\nTime: %5\n\n")
                           .arg(QFileInfo(filePath).fileName())
                           .arg(QFileInfo(signatureFile).fileName())
                           .arg(result.isValid ? "VALID" : "INVALID")
                           .arg(QString::fromStdString(result.signerInfo))
                           .arg(QString::fromStdString(result.timestamp));
        
        signatureResultArea->append(resultText);
        
        if (result.isValid) {
            logMessage("Signature verification successful - Signature is valid");
        } else {
            logMessage("Signature verification failed - Signature is invalid");
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Signature verification failed: %1").arg(e.what()));
        logMessage("Signature verification error: " + QString(e.what()));
    }
    
    updateProgressBar(-1);
}

void MainWindow::onInitStorage() {
    bool ok;
    QString password = QInputDialog::getText(this, "Initialize Storage", 
                                           "Enter master password:", 
                                           QLineEdit::Password, "", &ok);
    if (!ok || password.isEmpty()) return;
    
    QString confirmPassword = QInputDialog::getText(this, "Initialize Storage", 
                                                  "Confirm master password:", 
                                                  QLineEdit::Password, "", &ok);
    if (!ok || confirmPassword != password) {
        QMessageBox::warning(this, "Warning", "Passwords do not match.");
        return;
    }
    
    try {
        auto result = secureStorage->initialize(password.toStdString());
        
        if (result.success) {
            storageLogArea->append("Secure storage initialized successfully\n");
            logMessage("Secure storage initialized successfully");
        } else {
            QMessageBox::critical(this, "Storage Error", QString::fromStdString(result.message));
            storageLogArea->append("Storage initialization failed: " + 
                                 QString::fromStdString(result.message) + "\n");
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Storage initialization failed: %1").arg(e.what()));
        storageLogArea->append("Storage initialization error: " + QString(e.what()) + "\n");
    }
}

void MainWindow::onUnlockStorage() {
    bool ok;
    QString password = QInputDialog::getText(this, "Unlock Storage", 
                                           "Enter master password:", 
                                           QLineEdit::Password, "", &ok);
    if (!ok || password.isEmpty()) return;
    
    try {
        auto result = secureStorage->unlock(password.toStdString());
        
        if (result.success) {
            storageLogArea->append("Secure storage unlocked successfully\n");
            logMessage("Secure storage unlocked successfully");
        } else {
            QMessageBox::critical(this, "Storage Error", QString::fromStdString(result.message));
            storageLogArea->append("Storage unlock failed: " + 
                                 QString::fromStdString(result.message) + "\n");
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Storage unlock failed: %1").arg(e.what()));
        storageLogArea->append("Storage unlock error: " + QString(e.what()) + "\n");
    }
}

void MainWindow::onStoreFile() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Store");
    if (filePath.isEmpty()) return;
    
    bool ok;
    QString alias = QInputDialog::getText(this, "Store File", 
                                        "Enter alias for the file (optional):", 
                                        QLineEdit::Normal, 
                                        QFileInfo(filePath).baseName(), &ok);
    if (!ok) return;
    
    try {
        auto result = secureStorage->storeFile(filePath.toStdString(), alias.toStdString());
        
        if (result.success) {
            storageLogArea->append("File stored successfully: " + alias + "\n");
            logMessage("File stored successfully in secure storage");
        } else {
            QMessageBox::critical(this, "Storage Error", QString::fromStdString(result.message));
            storageLogArea->append("File storage failed: " + 
                                 QString::fromStdString(result.message) + "\n");
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("File storage failed: %1").arg(e.what()));
        storageLogArea->append("File storage error: " + QString(e.what()) + "\n");
    }
}

void MainWindow::onRetrieveFile() {
    auto files = secureStorage->listStoredFiles();
    if (files.empty()) {
        QMessageBox::information(this, "Info", "No files stored in secure storage.");
        return;
    }
    
    QStringList fileList;
    for (const auto& file : files) {
        fileList << QString::fromStdString(file);
    }
    
    bool ok;
    QString alias = QInputDialog::getItem(this, "Retrieve File", 
                                        "Select file to retrieve:", 
                                        fileList, 0, false, &ok);
    if (!ok || alias.isEmpty()) return;
    
    QString outputPath = QFileDialog::getSaveFileName(this, "Save Retrieved File");
    if (outputPath.isEmpty()) return;
    
    try {
        auto result = secureStorage->retrieveFile(alias.toStdString(), outputPath.toStdString());
        
        if (result.success) {
            storageLogArea->append("File retrieved successfully: " + alias + " -> " + 
                                 QFileInfo(outputPath).fileName() + "\n");
            logMessage("File retrieved successfully from secure storage");
        } else {
            QMessageBox::critical(this, "Storage Error", QString::fromStdString(result.message));
            storageLogArea->append("File retrieval failed: " + 
                                 QString::fromStdString(result.message) + "\n");
        }
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("File retrieval failed: %1").arg(e.what()));
        storageLogArea->append("File retrieval error: " + QString(e.what()) + "\n");
    }
}

void MainWindow::onListFiles() {
    try {
        auto files = secureStorage->listStoredFiles();
        
        storageLogArea->append("=== Stored Files ===\n");
        if (files.empty()) {
            storageLogArea->append("No files found in secure storage.\n");
        } else {
            for (const auto& file : files) {
                auto info = secureStorage->getFileInfo(file);
                if (info.success) {
                    storageLogArea->append(QString::fromStdString(file) + ":\n");
                    storageLogArea->append(QString::fromStdString(info.message) + "\n");
                }
            }
        }
        storageLogArea->append("===================\n\n");
        
        logMessage(QString("Listed %1 files in secure storage").arg(files.size()));
        
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Error", QString("Failed to list files: %1").arg(e.what()));
        storageLogArea->append("File listing error: " + QString(e.what()) + "\n");
    }
}

void MainWindow::onExit() {
    QApplication::quit();
}

void MainWindow::onAbout() {
    QMessageBox::about(this, "About Cryptography Application",
        "Cryptography Application v1.0\n\n"
        "A comprehensive cryptographic tool featuring:\n"
        "• AES-256, RSA-2048, and Blowfish encryption\n"
        "• MD5 and SHA-256 hash functions\n"
        "• Digital signatures with RSA\n"
        "• Secure file storage\n\n"
        "Built with OpenSSL, Crypto++, Boost, and Qt5\n"
        "© 2025 Cryptography Application");
}

void MainWindow::onAlgorithmChanged() {
    QString algorithm = algorithmCombo->currentText();
    logMessage("Selected encryption algorithm: " + algorithm);
}

void MainWindow::onHashAlgorithmChanged() {
    QString algorithm = hashAlgorithmCombo->currentText();
    logMessage("Selected hash algorithm: " + algorithm);
}

} // namespace CryptoApp
