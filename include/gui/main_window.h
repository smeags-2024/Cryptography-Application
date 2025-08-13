#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QProgressBar>
#include "common/types.h"

QT_BEGIN_NAMESPACE
class QAction;
class QMenu;
QT_END_NAMESPACE

namespace CryptoApp {

    class MainWindow : public QMainWindow {
        Q_OBJECT

    private:
        // Crypto components
        class AESCrypto* aes;
        class RSACrypto* rsa;
        class BlowfishCrypto* blowfish;
        class HashFunctions* hashFunc;
        class DigitalSignature* digitalSig;
        class SecureStorage* secureStorage;
        
        // UI components
        QTabWidget* centralTabs;
        QStatusBar* m_statusBar;
        QProgressBar* progressBar;
        
        // Encryption tab
        QWidget* encryptionTab;
        QComboBox* algorithmCombo;
        QPushButton* encryptFileBtn;
        QPushButton* decryptFileBtn;
        QPushButton* generateKeyBtn;
        QTextEdit* keyDisplayArea;
        QTextEdit* logArea;
        
        // Hash tab
        QWidget* hashTab;
        QComboBox* hashAlgorithmCombo;
        QPushButton* calculateHashBtn;
        QPushButton* verifyHashBtn;
        QTextEdit* hashResultArea;
        
        // Signature tab
        QWidget* signatureTab;
        QPushButton* generateKeyPairBtn;
        QPushButton* signFileBtn;
        QPushButton* verifySignatureBtn;
        QTextEdit* publicKeyArea;
        QTextEdit* privateKeyArea;
        QTextEdit* signatureResultArea;
        
        // Storage tab
        QWidget* storageTab;
        QPushButton* initStorageBtn;
        QPushButton* unlockStorageBtn;
        QPushButton* storeFileBtn;
        QPushButton* retrieveFileBtn;
        QPushButton* listFilesBtn;
        QTextEdit* storageLogArea;
        
        // Settings tab
        QWidget* settingsTab;
        
        // Menus and actions
        QMenuBar* m_menuBar;
        QMenu* fileMenu;
        QMenu* toolsMenu;
        QMenu* helpMenu;
        QAction* exitAction;
        QAction* aboutAction;
        
        void createMenus();
        void createActions();
        void createEncryptionTab();
        void createHashTab();
        void createSignatureTab();
        void createStorageTab();
        void createSettingsTab();
        void setupStatusBar();
        
        void logMessage(const QString& message);
        void updateProgressBar(int value);
        
    public:
        MainWindow(QWidget* parent = nullptr);
        ~MainWindow();

    private slots:
        // Encryption slots
        void onEncryptFile();
        void onDecryptFile();
        void onGenerateKey();
        
        // Hash slots
        void onCalculateHash();
        void onVerifyHash();
        
        // Signature slots
        void onGenerateKeyPair();
        void onSignFile();
        void onVerifySignature();
        
        // Storage slots
        void onInitStorage();
        void onUnlockStorage();
        void onStoreFile();
        void onRetrieveFile();
        void onListFiles();
        
        // Menu slots
        void onExit();
        void onAbout();
        
        // Utility slots
        void onAlgorithmChanged();
        void onHashAlgorithmChanged();
    };

} // namespace CryptoApp

#endif // MAIN_WINDOW_H
