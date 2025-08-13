#ifndef ENCRYPTION_DIALOG_H
#define ENCRYPTION_DIALOG_H

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QLabel>
#include "common/types.h"

namespace CryptoApp {

    class EncryptionDialog : public QDialog {
        Q_OBJECT

    private:
        QComboBox* algorithmCombo;
        QLineEdit* inputFileEdit;
        QLineEdit* outputFileEdit;
        QLineEdit* keyEdit;
        QPushButton* browseInputBtn;
        QPushButton* browseOutputBtn;
        QPushButton* generateKeyBtn;
        QPushButton* encryptBtn;
        QPushButton* cancelBtn;
        QTextEdit* logArea;
        QProgressBar* progressBar;
        QLabel* statusLabel;
        
        void setupUI();
        void connectSignals();
        
    public:
        explicit EncryptionDialog(QWidget* parent = nullptr);
        ~EncryptionDialog();
        
        void setAlgorithm(EncryptionAlgorithm algorithm);
        void setInputFile(const QString& filePath);
        void setOutputFile(const QString& filePath);
        void setKey(const QString& key);
        
        QString getInputFile() const;
        QString getOutputFile() const;
        QString getKey() const;
        EncryptionAlgorithm getAlgorithm() const;

    private slots:
        void onBrowseInputFile();
        void onBrowseOutputFile();
        void onGenerateKey();
        void onEncrypt();
        void onCancel();
        void onAlgorithmChanged();
        
    signals:
        void encryptionRequested(const QString& inputFile, 
                               const QString& outputFile,
                               const QString& key,
                               EncryptionAlgorithm algorithm);
    };

} // namespace CryptoApp

#endif // ENCRYPTION_DIALOG_H
