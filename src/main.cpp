#include "gui/main_window.h"
#include <QtWidgets/QApplication>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QStyleFactory>
#include <QtCore/QDir>
#include <QtCore/QStandardPaths>
#include <iostream>
#include <exception>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    // Set application properties
    app.setApplicationName("Cryptography Application");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("CryptoApp");
    app.setOrganizationDomain("cryptoapp.com");
    
    try {
        // Set application style
        app.setStyle(QStyleFactory::create("Fusion"));
        
        // Create and apply dark theme
        QPalette darkPalette;
        darkPalette.setColor(QPalette::Window, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::WindowText, Qt::white);
        darkPalette.setColor(QPalette::Base, QColor(25, 25, 25));
        darkPalette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::ToolTipBase, Qt::white);
        darkPalette.setColor(QPalette::ToolTipText, Qt::white);
        darkPalette.setColor(QPalette::Text, Qt::white);
        darkPalette.setColor(QPalette::Button, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::ButtonText, Qt::white);
        darkPalette.setColor(QPalette::BrightText, Qt::red);
        darkPalette.setColor(QPalette::Link, QColor(42, 130, 218));
        darkPalette.setColor(QPalette::Highlight, QColor(42, 130, 218));
        darkPalette.setColor(QPalette::HighlightedText, Qt::black);
        app.setPalette(darkPalette);
        
        // Ensure data directory exists
        QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(dataDir);
        
        // Create main window
        CryptoApp::MainWindow window;
        
        // Show the main window
        window.show();
        
        std::cout << "Cryptography Application started successfully!" << std::endl;
        std::cout << "Features available:" << std::endl;
        std::cout << "  - AES-256, RSA-2048, and Blowfish encryption" << std::endl;
        std::cout << "  - MD5 and SHA-256 hash functions" << std::endl;
        std::cout << "  - Digital signatures with RSA" << std::endl;
        std::cout << "  - Secure file storage system" << std::endl;
        std::cout << "  - Graphical User Interface" << std::endl;
        
        return app.exec();
        
    } catch (const std::exception& e) {
        QString errorMsg = QString("Fatal error: %1").arg(e.what());
        std::cerr << errorMsg.toStdString() << std::endl;
        
        // Try to show error dialog if possible
        QMessageBox::critical(nullptr, "Fatal Error", errorMsg);
        return -1;
        
    } catch (...) {
        QString errorMsg = "Unknown fatal error occurred";
        std::cerr << errorMsg.toStdString() << std::endl;
        
        QMessageBox::critical(nullptr, "Fatal Error", errorMsg);
        return -1;
    }
}
