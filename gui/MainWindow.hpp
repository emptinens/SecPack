#pragma once
#include <QMainWindow>
#include <vector>
#include <cstdint>
class QLineEdit;
class QDoubleSpinBox;
class QSpinBox;
class QTextEdit;
class QLabel;
class QTabWidget;

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget* parent=nullptr);

private:
  // Pack
  QLineEdit *inEdit, *outEdit, *keyEdit;
  QDoubleSpinBox *redSpin;
  // Unpack
  QLineEdit *inEncEdit, *outPlainEdit, *keyEdit2;
  QSpinBox *passesSpin;
  // Hash
  QLineEdit *hashEdit, *hashOut;
  // Hash Compare
  QLineEdit *hashAEdit, *hashBEdit, *hashCmpOut;
  // Profile
  QLabel *profileNameLabel;
  QTextEdit *sysInfoView;
  // Settings
  QLineEdit *accentEdit;
  QDoubleSpinBox *defaultReductionSpin;
  QLineEdit *defaultBlockSizeEdit;

  QTextEdit *log;
  QTabWidget *tabs;

  // Config state
  QString cfgPath;
  QString themeMode; // "grey" or "white"
  QString accentColor; // #RRGGBB
  double defaultReduction{0.6};
  quint64 defaultBlockSize{8ull<<20};

  // Actions
  std::vector<uint8_t> readKey(const QString& p);
  void generateKeyInteractive(QLineEdit* targetField);
  void onGenKeyPack();
  void onGenKeyUnpack();
  void onPack();
  void onUnpack();
  void onHash();
  void onHashCompare();

  // Profile/Settings
  void loadConfig();
  void saveConfig();
  void applyTheme();
  void applyDefaultsToUi();
  QString collectSystemInfo() const;
  void makeInfoButton(QWidget* parentRow, const QString& title, const QString& text);
};
