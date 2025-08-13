#ifndef SIGNATURE_DIALOG_H
#define SIGNATURE_DIALOG_H

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTabWidget>
#include "common/types.h"

namespace CryptoApp {

    class SignatureDialog : public QDialog {
        Q_OBJECT

    private:
        QTabWidget* tabWidget;
        
        // Sign tab
        QWidget* signTab;
        QLineEdit* signFileEdit;
        QLineEdit* signatureFileEdit;
        QTextEdit* privateKeyEdit;
        QPushButton* browseSignFileBtn;
        QPushButton* browseSignatureFileBtn;
        QPushButton* loadPrivateKeyBtn;
        QPushButton* signBtn;
        
        // Verify tab
        QWidget* verifyTab;
        QLineEdit* verifyFileEdit;
        QLineEdit* verifySignatureFileEdit;
        QTextEdit* publicKeyEdit;
        QPushButton* browseVerifyFileBtn;
        QPushButton* browseVerifySignatureFileBtn;
        QPushButton* loadPublicKeyBtn;
        QPushButton* verifyBtn;
        
        // Common controls
        QComboBox* hashAlgorithmCombo;
        QPushButton* generateKeyPairBtn;
        QPushButton* closeBtn;
        QTextEdit* resultArea;
        QProgressBar* progressBar;
        QLabel* statusLabel;
        
        void setupUI();
        void connectSignals();
        void setupSignTab();
        void setupVerifyTab();
        
    public:
        explicit SignatureDialog(QWidget* parent = nullptr);
        ~SignatureDialog();
        
        void setHashAlgorithm(HashAlgorithm algorithm);
        HashAlgorithm getHashAlgorithm() const;

    private slots:
        void onBrowseSignFile();
        void onBrowseSignatureFile();
        void onLoadPrivateKey();
        void onSign();
        
        void onBrowseVerifyFile();
        void onBrowseVerifySignatureFile();
        void onLoadPublicKey();
        void onVerify();
        
        void onGenerateKeyPair();
        void onClose();
        void onHashAlgorithmChanged();
        
    signals:
        void signRequested(const QString& filePath, 
                         const QString& signatureFile,
                         const QString& privateKey,
                         HashAlgorithm hashAlgorithm);
        
        void verifyRequested(const QString& filePath, 
                           const QString& signatureFile,
                           const QString& publicKey,
                           HashAlgorithm hashAlgorithm);
    };

} // namespace CryptoApp

#endif // SIGNATURE_DIALOG_H
