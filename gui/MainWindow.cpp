#include "MainWindow.hpp"
#include <QFileDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QTextEdit>
#include <QDoubleSpinBox>
#include <QSpinBox>
#include <QMessageBox>
#include <QFile>
#include <QRandomGenerator>
#include <QDir>
#include <QFileInfo>
#include <QTabWidget>
#include <QApplication>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSysInfo>
#include <QProcess>
#include <QFontDatabase>
#include <QIcon>
#include "compress.hpp"
#include "crypto.hpp"
#include "tar.hpp"

static QString readProcessOutput(const QString& cmd, const QStringList& args) {
  QProcess p; p.start(cmd, args); p.waitForFinished(1500); return QString::fromUtf8(p.readAllStandardOutput());
}

void MainWindow::applyTheme() {
  QString glow = themeMode == "white" ? "box-shadow: 0 0 0 1px rgba(0,0,0,.08), 0 8px 30px rgba(0,0,0,.08);" : "box-shadow: 0 0 0 1px rgba(255,255,255,.05), 0 8px 30px rgba(0,0,0,.4);";
  if (themeMode == "white") {
    qApp->setStyleSheet(QString(R"(
    QWidget { background: #fbfbfd; color: #14171a; }
    QTabWidget::pane { border: 1px solid #e6e8eb; border-radius: 12px; padding: 6px; background: #ffffff; %1 }
    QTabBar::tab { background: #f1f3f5; color: #2a2f35; border: 1px solid #e6e8eb; padding: 8px 14px; border-top-left-radius: 10px; border-top-right-radius: 10px; margin: 0 6px; }
    QTabBar::tab:selected { background: #ffffff; color: #0f1113; }
    QLineEdit, QTextEdit { background: #ffffff; border: 1px solid #e6e8eb; border-radius: 10px; padding: 8px 10px; color: #14171a; }
    QLabel { color: #4b5560; }
    QPushButton { background: %2; color: #ffffff; border: none; padding: 10px 14px; border-radius: 10px; font-weight: 600; }
    QPushButton#secondary { background: #e9ecef; color: #14171a; }
  )").arg(glow, accentColor));
  } else {
    qApp->setStyleSheet(QString(R"(
    QWidget { background-color: #0f1113; color: #e6e7e8; font-family: 'Inter', 'Segoe UI', sans-serif; }
    QTabWidget::pane { border: 1px solid #262a2e; border-radius: 12px; padding: 6px; background: #111418; %1 }
    QTabBar::tab { background: #0f1113; color: #cfd3d7; border: 1px solid #262a2e; padding: 8px 14px; border-top-left-radius: 10px; border-top-right-radius: 10px; margin: 0 6px; }
    QTabBar::tab:selected { background: #151a1f; color: #e6e7e8; }
    QLineEdit, QTextEdit { background: #0d0f12; border: 1px solid #262a2e; border-radius: 10px; padding: 8px 10px; color: #e6e7e8; }
    QLabel { color: #a8adb3; }
    QPushButton { background: %2; color: #0b0d12; border: none; padding: 10px 14px; border-radius: 10px; font-weight: 600; }
    QPushButton#secondary { background: #2b2f34; color: #e6e7e8; }
  )").arg(glow, accentColor));
  }
}

void MainWindow::loadConfig() {
  cfgPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/secpack/config.json";
  QDir().mkpath(QFileInfo(cfgPath).path());
  QFile f(cfgPath);
  if (f.exists() && f.open(QIODevice::ReadOnly)) {
    auto doc = QJsonDocument::fromJson(f.readAll()); f.close();
    auto o = doc.object();
    themeMode = o.value("theme").toString("grey");
    accentColor = o.value("accent").toString("#2c90ff");
    defaultReduction = o.value("defaultReduction").toDouble(0.6);
    defaultBlockSize = (quint64) o.value("defaultBlockSize").toDouble(8ull<<20);
  } else {
    themeMode = "grey"; accentColor = "#2c90ff"; defaultReduction = 0.6; defaultBlockSize = 8ull<<20;
  }
}

void MainWindow::saveConfig() {
  QJsonObject o; o["theme"] = themeMode; o["accent"] = accentColor; o["defaultReduction"] = defaultReduction; o["defaultBlockSize"] = (double) defaultBlockSize;
  QDir().mkpath(QFileInfo(cfgPath).path());
  QFile f(cfgPath); if (f.open(QIODevice::WriteOnly)) { f.write(QJsonDocument(o).toJson()); f.close(); }
}

QString MainWindow::collectSystemInfo() const {
  QString user = qEnvironmentVariable("USER"); if (user.isEmpty()) user = qEnvironmentVariable("USERNAME");
  QString os = QSysInfo::prettyProductName();
  QString kernel = readProcessOutput("uname", {"-r"}).trimmed();
  QString cpu = readProcessOutput("bash", {"-lc", R"(lscpu | sed -n 's/^Model name:[ ]*//p' | head -n1)"}).trimmed();
  QString mem;
  QFile mf("/proc/meminfo");
  if (mf.open(QIODevice::ReadOnly)) {
    while (!mf.atEnd()) {
      QByteArray line = mf.readLine();
      if (line.startsWith("MemTotal:")) {
        QString s = QString::fromUtf8(line).trimmed();
        // s like: "MemTotal:       16305080 kB"
        mem = s.section(':', 1).trimmed();
        break;
      }
    }
    mf.close();
  } else {
    mem = "unknown";
  }
  QString gpu = readProcessOutput("bash", {"-lc", R"(lspci | sed -n 's/^[^:]*: //p' | grep -i -E 'vga|3d' | head -n1)"}).trimmed();
  QString shell = qEnvironmentVariable("SHELL");
  return QString("User: %1\nOS: %2\nKernel: %3\nCPU: %4\nMem: %5\nGPU: %6\nShell: %7").arg(user, os, kernel, cpu, mem, gpu, shell);
}

void MainWindow::makeInfoButton(QWidget* parentRow, const QString& title, const QString& text) {
  auto* btn = new QPushButton("i"); btn->setObjectName("secondary"); btn->setFixedWidth(28);
  QObject::connect(btn, &QPushButton::clicked, this, [=]{ QMessageBox::information(this, title, text); });
  static_cast<QHBoxLayout*>(parentRow->layout())->addWidget(btn);
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
  loadConfig();
  applyTheme();

  // Fonts and window icon
  QFont f = qApp->font(); f.setFamily("Inter, Segoe UI, Cantarell, Ubuntu, Noto Sans, sans-serif"); qApp->setFont(f);
  setWindowIcon(QIcon::fromTheme("security-high"));

  auto* central = new QWidget;
  auto* root = new QVBoxLayout;
  root->setContentsMargins(18, 18, 18, 18);
  root->setSpacing(14);

  auto* header = new QLabel("SecPack");
  QFont hf = header->font(); hf.setPointSize(hf.pointSize() + 6); hf.setBold(true); header->setFont(hf);
  root->addWidget(header);

  tabs = new QTabWidget;

  // Pack tab
  auto* packTab = new QWidget; auto* pv = new QVBoxLayout; pv->setContentsMargins(12,12,12,12); packTab->setLayout(pv);
  auto* inRow = new QWidget; auto* inL = new QHBoxLayout; inRow->setLayout(inL); inEdit = new QLineEdit; inEdit->setPlaceholderText("Select input file…"); auto* inBtn = new QPushButton("Browse"); inBtn->setObjectName("secondary");
  inL->addWidget(new QLabel("Input")); inL->addWidget(inEdit); inL->addWidget(inBtn); makeInfoButton(inRow, "Input", "File to compress+encrypt");
  auto* outRow = new QWidget; auto* outL = new QHBoxLayout; outRow->setLayout(outL); outEdit = new QLineEdit; outEdit->setPlaceholderText("Choose output .enc…"); auto* outBtn = new QPushButton("Save as"); outBtn->setObjectName("secondary");
  outL->addWidget(new QLabel("Output")); outL->addWidget(outEdit); outL->addWidget(outBtn); makeInfoButton(outRow, "Output", ".enc result");
  auto* keyRow = new QWidget; auto* keyL = new QHBoxLayout; keyRow->setLayout(keyL); keyEdit = new QLineEdit; keyEdit->setPlaceholderText("Key file (32 bytes)…"); auto* keyBtn = new QPushButton("Browse"); keyBtn->setObjectName("secondary"); auto* keyGenBtn = new QPushButton("Generate key");
  keyL->addWidget(new QLabel("Key")); keyL->addWidget(keyEdit); keyL->addWidget(keyBtn); keyL->addWidget(keyGenBtn); makeInfoButton(keyRow, "Key", "Generated 32-byte key used for AES");
  auto* redRow = new QWidget; auto* redL = new QHBoxLayout; redRow->setLayout(redL); redSpin = new QDoubleSpinBox; redSpin->setRange(0.1,0.9); redSpin->setSingleStep(0.05); redSpin->setValue(defaultReduction);
  redL->addWidget(new QLabel("Reduction target")); redL->addWidget(redSpin); makeInfoButton(redRow, "Reduction", "Target overall compression ratio");
  auto* packBtn = new QPushButton("Pack");
  pv->addWidget(inRow); pv->addWidget(outRow); pv->addWidget(keyRow); pv->addWidget(redRow); pv->addWidget(packBtn);

  // Unpack tab
  auto* unpackTab = new QWidget; auto* uv = new QVBoxLayout; uv->setContentsMargins(12,12,12,12); unpackTab->setLayout(uv);
  auto* inEncRow = new QWidget; auto* inEncL = new QHBoxLayout; inEncRow->setLayout(inEncL); inEncEdit = new QLineEdit; inEncEdit->setPlaceholderText("Select .enc file…"); auto* inEncBtn = new QPushButton("Browse"); inEncBtn->setObjectName("secondary");
  inEncL->addWidget(new QLabel("Encrypted")); inEncL->addWidget(inEncEdit); inEncL->addWidget(inEncBtn); makeInfoButton(inEncRow, "Encrypted", "Encrypted .enc file");
  auto* outPlainRow = new QWidget; auto* outPlainL = new QHBoxLayout; outPlainRow->setLayout(outPlainL); outPlainEdit = new QLineEdit; outPlainEdit->setPlaceholderText("Choose output file…"); auto* outPlainBtn = new QPushButton("Save as"); outPlainBtn->setObjectName("secondary");
  outPlainL->addWidget(new QLabel("Output")); outPlainL->addWidget(outPlainEdit); outPlainL->addWidget(outPlainBtn);
  auto* keyRow2 = new QWidget; auto* key2L = new QHBoxLayout; keyRow2->setLayout(key2L); keyEdit2 = new QLineEdit; keyEdit2->setPlaceholderText("Key file (32 bytes)…"); auto* keyBtn2 = new QPushButton("Browse"); keyBtn2->setObjectName("secondary"); auto* keyGenBtn2 = new QPushButton("Generate key");
  key2L->addWidget(new QLabel("Key")); key2L->addWidget(keyEdit2); key2L->addWidget(keyBtn2); key2L->addWidget(keyGenBtn2);
  auto* passesRow = new QWidget; auto* passesL = new QHBoxLayout; passesRow->setLayout(passesL); passesSpin = new QSpinBox; passesSpin->setRange(0,64); passesSpin->setValue(0);
  passesL->addWidget(new QLabel("Passes (0=auto)")); passesL->addWidget(passesSpin); makeInfoButton(passesRow, "Passes", "Number of XZ passes used during packing");
  auto* unpackBtn = new QPushButton("Unpack");
  uv->addWidget(inEncRow); uv->addWidget(outPlainRow); uv->addWidget(keyRow2); uv->addWidget(passesRow); uv->addWidget(unpackBtn);

  // Hash tab
  auto* hashTab = new QWidget; auto* hv = new QVBoxLayout; hv->setContentsMargins(12,12,12,12); hashTab->setLayout(hv);
  auto* hashRow = new QWidget; auto* hashL = new QHBoxLayout; hashRow->setLayout(hashL); hashEdit = new QLineEdit; hashEdit->setPlaceholderText("Select file…"); auto* hashBtn = new QPushButton("Browse"); hashBtn->setObjectName("secondary");
  hashL->addWidget(new QLabel("File")); hashL->addWidget(hashEdit); hashL->addWidget(hashBtn);
  hashOut = new QLineEdit; hashOut->setReadOnly(true); hashOut->setPlaceholderText("SHA-256 will appear here");
  hv->addWidget(hashRow); hv->addWidget(hashOut);

  // Hash Compare tab
  auto* cmpTab = new QWidget; auto* cv = new QVBoxLayout; cmpTab->setLayout(cv);
  auto* aRow = new QWidget; auto* aL = new QHBoxLayout; aRow->setLayout(aL); hashAEdit = new QLineEdit; auto* aBtn = new QPushButton("File A"); aBtn->setObjectName("secondary");
  aL->addWidget(new QLabel("File A")); aL->addWidget(hashAEdit); aL->addWidget(aBtn);
  auto* bRow = new QWidget; auto* bL = new QHBoxLayout; bRow->setLayout(bL); hashBEdit = new QLineEdit; auto* bBtn = new QPushButton("File B"); bBtn->setObjectName("secondary");
  bL->addWidget(new QLabel("File B")); bL->addWidget(hashBEdit); bL->addWidget(bBtn);
  auto* cmpBtn = new QPushButton("Compare SHA-256");
  hashCmpOut = new QLineEdit; hashCmpOut->setReadOnly(true);
  cv->addWidget(aRow); cv->addWidget(bRow); cv->addWidget(cmpBtn); cv->addWidget(hashCmpOut);

  // Profile tab
  auto* profileTab = new QWidget; auto* pr = new QVBoxLayout; profileTab->setLayout(pr);
  QString user = qEnvironmentVariable("USER"); if (user.isEmpty()) user = qEnvironmentVariable("USERNAME");
  profileNameLabel = new QLabel(QString("Profile: %1").arg(user));
  sysInfoView = new QTextEdit; sysInfoView->setReadOnly(true); sysInfoView->setMinimumHeight(160);
  sysInfoView->setText(collectSystemInfo());
  pr->addWidget(profileNameLabel); pr->addWidget(sysInfoView);

  // Settings tab
  auto* settingsTab = new QWidget; auto* sv = new QVBoxLayout; settingsTab->setLayout(sv);
  auto* themeRow = new QWidget; auto* thL = new QHBoxLayout; themeRow->setLayout(thL);
  auto* greyBtn = new QPushButton("Grey theme"); greyBtn->setObjectName("secondary");
  auto* whiteBtn = new QPushButton("White theme"); whiteBtn->setObjectName("secondary");
  thL->addWidget(new QLabel("Theme")); thL->addWidget(greyBtn); thL->addWidget(whiteBtn);
  auto* accentRow = new QWidget; auto* acL = new QHBoxLayout; accentRow->setLayout(acL); accentEdit = new QLineEdit; accentEdit->setText(accentColor);
  acL->addWidget(new QLabel("Accent #RRGGBB")); acL->addWidget(accentEdit);
  auto* reduRow = new QWidget; auto* drL = new QHBoxLayout; reduRow->setLayout(drL); defaultReductionSpin = new QDoubleSpinBox; defaultReductionSpin->setRange(0.1,0.9); defaultReductionSpin->setSingleStep(0.05); defaultReductionSpin->setValue(defaultReduction);
  drL->addWidget(new QLabel("Default reduction")); drL->addWidget(defaultReductionSpin);
  auto* blkDefRow = new QWidget; auto* bdL = new QHBoxLayout; blkDefRow->setLayout(bdL); defaultBlockSizeEdit = new QLineEdit; defaultBlockSizeEdit->setText(QString::number(defaultBlockSize));
  bdL->addWidget(new QLabel("Default block size")); bdL->addWidget(defaultBlockSizeEdit);
  auto* saveBtn = new QPushButton("Save settings");
  sv->addWidget(themeRow); sv->addWidget(accentRow); sv->addWidget(reduRow); sv->addWidget(blkDefRow); sv->addWidget(saveBtn);

  tabs->addTab(packTab, "Pack");
  tabs->addTab(unpackTab, "Unpack");
  tabs->addTab(hashTab, "Hash");
  tabs->addTab(cmpTab, "Compare");
  tabs->addTab(profileTab, "Profile");
  tabs->addTab(settingsTab, "Settings");

  log = new QTextEdit; log->setReadOnly(true); log->setMinimumHeight(120);
  root->addWidget(tabs); root->addWidget(log);

  central->setLayout(root);
  setCentralWidget(central);
  setWindowTitle("SecPack");
  resize(860, 700);

  // Wire actions
  connect(greyBtn, &QPushButton::clicked, this, [&]{ themeMode = "grey"; applyTheme(); saveConfig(); });
  connect(whiteBtn, &QPushButton::clicked, this, [&]{ themeMode = "white"; applyTheme(); saveConfig(); });
  connect(saveBtn, &QPushButton::clicked, this, [&]{ accentColor = accentEdit->text(); defaultReduction = defaultReductionSpin->value(); defaultBlockSize = defaultBlockSizeEdit->text().toULongLong(); redSpin->setValue(defaultReduction); saveConfig(); });

  connect(inBtn, &QPushButton::clicked, this, [=]{ inEdit->setText(QFileDialog::getOpenFileName(this, "Select input")); });
  connect(outBtn, &QPushButton::clicked, this, [=]{ outEdit->setText(QFileDialog::getSaveFileName(this, "Select output .enc")); });
  connect(keyBtn, &QPushButton::clicked, this, [=]{ keyEdit->setText(QFileDialog::getOpenFileName(this, "Select key (32 bytes)")); });
  connect(inEncBtn, &QPushButton::clicked, this, [=]{ inEncEdit->setText(QFileDialog::getOpenFileName(this, "Select .enc file")); });
  connect(outPlainBtn, &QPushButton::clicked, this, [=]{ outPlainEdit->setText(QFileDialog::getSaveFileName(this, "Select output")); });
  connect(keyBtn2, &QPushButton::clicked, this, [=]{ keyEdit2->setText(QFileDialog::getOpenFileName(this, "Select key (32 bytes)")); });
  connect(hashBtn, &QPushButton::clicked, this, [=]{ hashEdit->setText(QFileDialog::getOpenFileName(this, "Select file")); });

  connect(keyGenBtn, &QPushButton::clicked, this, [&]{
    try {
      auto k = secpack::generate_secure_key(32);
      QString path = QFileDialog::getSaveFileName(this, "Save key file");
      if (!path.isEmpty()) { QFile f(path); if (f.open(QIODevice::WriteOnly)) { f.write((const char*)k.data(), (int)k.size()); f.close(); keyEdit->setText(path);} }
    } catch (const std::exception& e) { QMessageBox::warning(this, "Key", e.what()); }
  });
  connect(keyGenBtn2, &QPushButton::clicked, this, [&]{
    try {
      auto k = secpack::generate_secure_key(32);
      QString path = QFileDialog::getSaveFileName(this, "Save key file");
      if (!path.isEmpty()) { QFile f(path); if (f.open(QIODevice::WriteOnly)) { f.write((const char*)k.data(), (int)k.size()); f.close(); keyEdit2->setText(path);} }
    } catch (const std::exception& e) { QMessageBox::warning(this, "Key", e.what()); }
  });
  connect(packBtn, &QPushButton::clicked, this, [&]{ onPack(); });
  connect(unpackBtn, &QPushButton::clicked, this, [&]{ onUnpack(); });
  connect(cmpBtn, &QPushButton::clicked, this, [&]{ onHashCompare(); });
}

std::vector<uint8_t> MainWindow::readKey(const QString& p) {
  QFile f(p);
  if (!f.open(QIODevice::ReadOnly)) throw std::runtime_error("cannot open key");
  auto d = f.readAll();
  if (d.size() < 32) throw std::runtime_error("key must be at least 32 bytes");
  std::vector<uint8_t> k(32);
  memcpy(k.data(), d.constData(), 32);
  return k;
}

void MainWindow::generateKeyInteractive(QLineEdit* targetField) { /* unused now */ }

void MainWindow::onPack() {
  try {
    QString in = inEdit->text(), out = outEdit->text(), keyf = keyEdit->text();
    if (in.isEmpty() || out.isEmpty() || keyf.isEmpty()) throw std::runtime_error("fill fields");
    double reduction = redSpin->value();
    secpack::CompressMeta meta;
    QString solid = out + ".solid.xz";
    if (!secpack::xz_compress_multi(in.toStdString(), solid.toStdString(), reduction, 0.02, 8, meta, 9))
      throw std::runtime_error("compression failed");
    auto key = readKey(keyf);
    secpack::EncResult er;
    if (!secpack::aes256ctr_encrypt_file(solid.toStdString(), out.toStdString(), key, er))
      throw std::runtime_error("encryption failed");
    QFile::remove(solid);
    log->append(QString("OK pack: passes=%1 original=%2 final=%3").arg(meta.passes).arg((qulonglong)meta.originalSize).arg((qulonglong)meta.finalSize));
  } catch (const std::exception& ex) {
    QMessageBox::warning(this, "Pack", ex.what());
  }
}

void MainWindow::onUnpack() {
  try {
    QString in = inEncEdit->text(), out = outPlainEdit->text(), keyf = keyEdit2->text();
    if (in.isEmpty() || out.isEmpty() || keyf.isEmpty()) throw std::runtime_error("fill fields");
    auto key = readKey(keyf);
    QString tmp = out + ".dec.tmp";
    if (!secpack::aes256ctr_decrypt_file(in.toStdString(), tmp.toStdString(), key))
      throw std::runtime_error("decryption failed");
    int passes = passesSpin->value();
    if (passes > 0) {
      if (!secpack::xz_decompress_passes(tmp.toStdString(), out.toStdString(), passes))
        throw std::runtime_error("decompression failed");
      QFile::remove(tmp);
    } else {
      if (secpack::xz_decompress_passes(tmp.toStdString(), out.toStdString(), 1)) {
        QFile::remove(tmp);
      } else {
        QFile::remove(out);
        QFile::rename(tmp, out);
      }
    }
    log->append("OK unpack");
  } catch (const std::exception& ex) {
    QMessageBox::warning(this, "Unpack", ex.what());
  }
}

void MainWindow::onHash() {
  try {
    QString p = hashEdit->text(); if (p.isEmpty()) throw std::runtime_error("select file");
    auto h = secpack::sha256_file(p.toStdString());
    hashOut->setText(QString::fromStdString(secpack::hex(h)));
  } catch (const std::exception& ex) {
    QMessageBox::warning(this, "Hash", ex.what());
  }
}

void MainWindow::onHashCompare() {
  try {
    QString a = hashAEdit->text(); QString b = hashBEdit->text();
    if (a.isEmpty() || b.isEmpty()) throw std::runtime_error("select both files");
    auto ha = secpack::sha256_file(a.toStdString());
    auto hb = secpack::sha256_file(b.toStdString());
    bool eq = (ha == hb);
    hashCmpOut->setText(eq ? "MATCH" : "DIFFERENT");
  } catch (const std::exception& ex) {
    QMessageBox::warning(this, "Compare", ex.what());
  }
}
