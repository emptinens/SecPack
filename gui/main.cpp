#include <QApplication>
#include "MainWindow.hpp"

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  MainWindow w; w.resize(700, 600); w.show();
  return app.exec();
}
