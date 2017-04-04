/********************************************************************************
** Form generated from reading UI file 'netfilter.ui'
**
** Created by: Qt User Interface Compiler version 5.8.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_NETFILTER_H
#define UI_NETFILTER_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_netfilter
{
public:
    QLabel *label;
    QLabel *label_2;
    QLineEdit *IPLineEdit;
    QLineEdit *PORTLineEdit;
    QLabel *label_4;
    QPushButton *Add_IP_Btn;
    QPushButton *Del_IP_Btn;
    QPushButton *Display_IP_Btn;
    QPushButton *Add_PORT_Btn;
    QPushButton *Del_PORT_Btn;
    QPushButton *Disay_PORT_Btn;
    QTextEdit *textEdit;
    QTextEdit *textview;

    void setupUi(QWidget *netfilter)
    {
        if (netfilter->objectName().isEmpty())
            netfilter->setObjectName(QStringLiteral("netfilter"));
        netfilter->resize(748, 443);
        label = new QLabel(netfilter);
        label->setObjectName(QStringLiteral("label"));
        label->setGeometry(QRect(120, 90, 31, 17));
        label_2 = new QLabel(netfilter);
        label_2->setObjectName(QStringLiteral("label_2"));
        label_2->setGeometry(QRect(410, 90, 51, 17));
        IPLineEdit = new QLineEdit(netfilter);
        IPLineEdit->setObjectName(QStringLiteral("IPLineEdit"));
        IPLineEdit->setGeometry(QRect(150, 86, 171, 31));
        PORTLineEdit = new QLineEdit(netfilter);
        PORTLineEdit->setObjectName(QStringLiteral("PORTLineEdit"));
        PORTLineEdit->setGeometry(QRect(470, 80, 181, 31));
        label_4 = new QLabel(netfilter);
        label_4->setObjectName(QStringLiteral("label_4"));
        label_4->setGeometry(QRect(320, 30, 121, 21));
        QFont font;
        font.setPointSize(17);
        font.setBold(true);
        font.setItalic(true);
        font.setWeight(75);
        label_4->setFont(font);
        Add_IP_Btn = new QPushButton(netfilter);
        Add_IP_Btn->setObjectName(QStringLiteral("Add_IP_Btn"));
        Add_IP_Btn->setGeometry(QRect(140, 190, 99, 27));
        Del_IP_Btn = new QPushButton(netfilter);
        Del_IP_Btn->setObjectName(QStringLiteral("Del_IP_Btn"));
        Del_IP_Btn->setGeometry(QRect(240, 190, 99, 27));
        Display_IP_Btn = new QPushButton(netfilter);
        Display_IP_Btn->setObjectName(QStringLiteral("Display_IP_Btn"));
        Display_IP_Btn->setGeometry(QRect(140, 230, 201, 27));
        Add_PORT_Btn = new QPushButton(netfilter);
        Add_PORT_Btn->setObjectName(QStringLiteral("Add_PORT_Btn"));
        Add_PORT_Btn->setGeometry(QRect(470, 190, 99, 27));
        Del_PORT_Btn = new QPushButton(netfilter);
        Del_PORT_Btn->setObjectName(QStringLiteral("Del_PORT_Btn"));
        Del_PORT_Btn->setGeometry(QRect(570, 190, 99, 27));
        Disay_PORT_Btn = new QPushButton(netfilter);
        Disay_PORT_Btn->setObjectName(QStringLiteral("Disay_PORT_Btn"));
        Disay_PORT_Btn->setGeometry(QRect(470, 230, 191, 27));
        textEdit = new QTextEdit(netfilter);
        textEdit->setObjectName(QStringLiteral("textEdit"));
        textEdit->setGeometry(QRect(140, 280, 511, 31));
        textview = new QTextEdit(netfilter);
        textview->setObjectName(QStringLiteral("textview"));
        textview->setGeometry(QRect(140, 340, 511, 78));

        retranslateUi(netfilter);

        QMetaObject::connectSlotsByName(netfilter);
    } // setupUi

    void retranslateUi(QWidget *netfilter)
    {
        netfilter->setWindowTitle(QApplication::translate("netfilter", "netfilter", Q_NULLPTR));
        label->setText(QApplication::translate("netfilter", "IP:", Q_NULLPTR));
        label_2->setText(QApplication::translate("netfilter", "\347\253\257\345\217\243\345\217\267:", Q_NULLPTR));
        IPLineEdit->setText(QString());
        label_4->setText(QApplication::translate("netfilter", "NETFILTER", Q_NULLPTR));
        Add_IP_Btn->setText(QApplication::translate("netfilter", "\346\267\273\345\212\240IP\345\234\260\345\235\200", Q_NULLPTR));
        Del_IP_Btn->setText(QApplication::translate("netfilter", "\345\210\240\351\231\244IP\345\234\260\345\235\200", Q_NULLPTR));
        Display_IP_Btn->setText(QApplication::translate("netfilter", "\346\230\276\347\244\272\350\277\207\346\273\244\347\232\204IP\345\234\260\345\235\200", Q_NULLPTR));
        Add_PORT_Btn->setText(QApplication::translate("netfilter", "\346\267\273\345\212\240\347\253\257\345\217\243\345\217\267", Q_NULLPTR));
        Del_PORT_Btn->setText(QApplication::translate("netfilter", "\345\210\240\351\231\244\347\253\257\345\217\243\345\217\267", Q_NULLPTR));
        Disay_PORT_Btn->setText(QApplication::translate("netfilter", "\346\230\276\347\244\272\350\277\207\346\273\244\347\232\204\347\253\257\345\217\243\345\217\267", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class netfilter: public Ui_netfilter {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_NETFILTER_H
