/********************************************************************************
** Form generated from reading UI file 'login.ui'
**
** Created by: Qt User Interface Compiler version 5.8.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_LOGIN_H
#define UI_LOGIN_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_login
{
public:
    QLineEdit *usrLineEdit;
    QLineEdit *pwdLineEdit;
    QLabel *usrLabel;
    QLabel *pwdLabel;
    QPushButton *loginBtn;
    QPushButton *exitBtn;

    void setupUi(QWidget *login)
    {
        if (login->objectName().isEmpty())
            login->setObjectName(QStringLiteral("login"));
        login->resize(545, 396);
        usrLineEdit = new QLineEdit(login);
        usrLineEdit->setObjectName(QStringLiteral("usrLineEdit"));
        usrLineEdit->setGeometry(QRect(230, 80, 113, 27));
        pwdLineEdit = new QLineEdit(login);
        pwdLineEdit->setObjectName(QStringLiteral("pwdLineEdit"));
        pwdLineEdit->setGeometry(QRect(230, 156, 113, 31));
        usrLabel = new QLabel(login);
        usrLabel->setObjectName(QStringLiteral("usrLabel"));
        usrLabel->setGeometry(QRect(170, 80, 51, 31));
        usrLabel->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextEditable);
        pwdLabel = new QLabel(login);
        pwdLabel->setObjectName(QStringLiteral("pwdLabel"));
        pwdLabel->setGeometry(QRect(190, 160, 41, 20));
        loginBtn = new QPushButton(login);
        loginBtn->setObjectName(QStringLiteral("loginBtn"));
        loginBtn->setGeometry(QRect(140, 230, 99, 27));
        exitBtn = new QPushButton(login);
        exitBtn->setObjectName(QStringLiteral("exitBtn"));
        exitBtn->setGeometry(QRect(290, 230, 99, 27));

        retranslateUi(login);
        QObject::connect(exitBtn, SIGNAL(clicked()), login, SLOT(close()));

        QMetaObject::connectSlotsByName(login);
    } // setupUi

    void retranslateUi(QWidget *login)
    {
        login->setWindowTitle(QApplication::translate("login", "User Login", Q_NULLPTR));
        usrLabel->setText(QApplication::translate("login", "<html><head/><body><p>\347\224\250\346\210\267\345\220\215:</p></body></html>", Q_NULLPTR));
        pwdLabel->setText(QApplication::translate("login", "<html><head/><body><p><span style=\" font-size:12pt;\">\345\257\206\347\240\201:</span></p></body></html>", Q_NULLPTR));
        loginBtn->setText(QApplication::translate("login", "\347\231\273\345\275\225", Q_NULLPTR));
        exitBtn->setText(QApplication::translate("login", "\351\200\200\345\207\272", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class login: public Ui_login {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_LOGIN_H
