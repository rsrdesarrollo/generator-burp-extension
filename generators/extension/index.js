"use strict";
const Generator = require("yeoman-generator");
const _ = require("lodash");
const path = require("path");
const process = require("process");
const fs = require("fs");

function makeJavaPackageName(name) {
  // If its a valid package name don't do anything
  if (/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+[0-9a-z_]$/i.test(name)) {
    return name;
  }

  return _.replace(_.snakeCase(name), /_/g, ".");
}

function makeJavaClassName(name) {
  return _.upperFirst(_.camelCase(name));
}

function packageToPath(name) {
  return path.join(..._.split(name, "."));
}

module.exports = class extends Generator {
  initializing() {
    this.props = {};
    this.packageDestDir = undefined;
    this.baseJavaDestDir = undefined;
  }

  async prompting() {
    this.generalProps = await this.prompt([
      {
        type: "input",
        name: "github",
        message: "Github User",
        default: this.user.github.username
      },
      {
        type: "input",
        name: "name",
        message: "Your extension name",
        default: makeJavaClassName(path.basename(process.cwd())),
        filter: makeJavaClassName
      }
    ]);

    this.codeProps = await this.prompt([
      {
        type: "input",
        name: "package",
        message: "Java Package",
        default: _.join(
          [
            "com",
            this.generalProps.github,
            "burp.extensions",
            _.snakeCase(this.generalProps.name)
          ],
          "."
        ),
        filter: makeJavaPackageName
      },
      {
        type: "checkbox",
        message: "Select available extension features",
        name: "classes",
        choices: [
          { name: "Extension Tab GUI", value: "tab" },
          { name: "Message Editor Tab GUI", value: "editor" },
          { name: "Context menu GUI", value: "menu" },
          { name: "HTTP Listener", value: "http_listener" },
          { name: "Proxy Listener", value: "proxy_listener" },
          { name: "Intruder payload generator", value: "intruder_generator" },
          { name: "Intruder payload processor", value: "intruder_processor" },
          { name: "Scanner check", value: "scanner_chack" },
          {
            name: "Scanner insert point provider",
            value: "scanner_insert_point"
          },
          { name: "Session handling action", value: "session" },
          { name: "Extension state listener", value: "state_listener" },
          { name: "Scanner listener", value: "scanner_listener" },
          { name: "Scope change listener", value: "scope_listener" }
        ]
      }
    ]);

    this.codeProps.classes = _.zipObject(
      this.codeProps.classes,
      Array(this.codeProps.classes.length).fill(true)
    );

    this.props = _.assign({}, this.generalProps, this.codeProps);

    this.baseJavaDestDir = this.destinationPath(
      path.join("src", "main", "java")
    );
    this.packageDestDir = path.join(
      this.baseJavaDestDir,
      packageToPath(this.props.package)
    );
  }

  writing() {
    this.fs.copy(
      this.templatePath("gradle/**"),
      this.destinationPath("gradle")
    );

    this.fs.copy(
      this.templatePath("gitignore"),
      this.destinationPath(".gitignore")
    );

    const copyNoTemplate = [
      "build.gradle",
      "gradlew",
      "gradlew.bat",
      "settings.gradle"
    ];

    copyNoTemplate.forEach(element => {
      this.fs.copy(this.templatePath(element), this.destinationPath(element));
    });

    fs.mkdirSync(this.packageDestDir, { recursive: true });

    this.fs.copyTpl(
      this.templatePath(path.join("src", "main", "java", "burp", "**")),
      path.join(this.baseJavaDestDir, "burp"),
      this.props
    );

    this.fs.copyTpl(
      this.templatePath(path.join("src", "main", "java", "main_package", "**")),
      this.packageDestDir,
      this.props
    );

    this._cleanUiClasses();
    this._cleanSessionClasses();
    this._cleanScannerClasses();
    this._cleanNetworkListenerClassess();
    this._cleanIntruderClasses();
    this._cleanEventListenersClasses();
  }

  _cleanUiClasses() {
    if (!this._checkClass("tab")) {
      this.fs.delete(path.join(this.packageDestDir, "ui", "Tab.java"));
      this.fs.delete(
        path.join(this.packageDestDir, "ui", "forms", "ExtensionTab.*")
      );
    }

    if (!this._checkClass("editor")) {
      this.fs.delete(
        path.join(this.packageDestDir, "ui", "MessageEditorTabFactory.java")
      );
      this.fs.delete(
        path.join(this.packageDestDir, "ui", "forms", "EditorForm.*")
      );
    }

    if (!this._checkClass("menu")) {
      this.fs.delete(path.join(this.packageDestDir, "ui", "ContextMenu.java"));
    }

    // Cleanup unused UI forder structure
    if (!this._checkClass("tab") && !this._checkClass("editor")) {
      this.fs.delete(path.join(this.packageDestDir, "ui", "forms"));
    }

    if (
      !this._checkClass("tab") &&
      !this._checkClass("editor") &&
      !this._checkClass("menu")
    ) {
      this.fs.delete(path.join(this.packageDestDir, "ui"));
    }
  }

  _cleanSessionClasses() {
    if (!this._checkClass("session")) {
      this.fs.delete(path.join(this.packageDestDir, "session"));
    }
  }

  _cleanScannerClasses() {
    if (!this._checkClass("scanner_chack")) {
      this.fs.delete(
        path.join(this.packageDestDir, "scanner", "ScannerCheck.java")
      );
    }

    if (!this._checkClass("scanner_insert_point")) {
      this.fs.delete(
        path.join(
          this.packageDestDir,
          "scanner",
          "ScannerInsertionPointProvider.java"
        )
      );
    }

    if (
      !this._checkClass("scanner_chack") &&
      !this._checkClass("scanner_insert_point")
    ) {
      this.fs.delete(path.join(this.packageDestDir, "scanner"));
    }
  }

  _cleanNetworkListenerClassess() {
    if (!this._checkClass("http_listener")) {
      this.fs.delete(
        path.join(this.packageDestDir, "network_listeners", "HTTPListener.java")
      );
    }

    if (!this._checkClass("proxy_listener")) {
      this.fs.delete(
        path.join(
          this.packageDestDir,
          "network_listeners",
          "ProxyListener.java"
        )
      );
    }

    if (
      !this._checkClass("http_listener") &&
      !this._checkClass("proxy_listener")
    ) {
      this.fs.delete(path.join(this.packageDestDir, "network_listeners"));
    }
  }

  _cleanIntruderClasses() {
    if (!this._checkClass("intruder_generator")) {
      this.fs.delete(
        path.join(
          this.packageDestDir,
          "intruder",
          "IntruderPayloadGeneratorFactory.java"
        )
      );
    }

    if (!this._checkClass("intruder_processor")) {
      this.fs.delete(
        path.join(
          this.packageDestDir,
          "intruder",
          "IntruderPayloadProcessor.java"
        )
      );
    }

    if (
      !this._checkClass("intruder_generator") &&
      !this._checkClass("intruder_processor")
    ) {
      this.fs.delete(path.join(this.packageDestDir, "intruder"));
    }
  }

  _cleanEventListenersClasses() {
    if (!this._checkClass("state_listener")) {
      this.fs.delete(
        path.join(
          this.packageDestDir,
          "event_listeners",
          "ExtensionStateListener.java"
        )
      );
    }

    if (!this._checkClass("scanner_listener")) {
      this.fs.delete(
        path.join(
          this.packageDestDir,
          "event_listeners",
          "ScannerListener.java"
        )
      );
    }

    if (!this._checkClass("scope_listener")) {
      this.fs.delete(
        path.join(
          this.packageDestDir,
          "event_listeners",
          "ScopeChangeListener.java"
        )
      );
    }

    if (
      !this._checkClass("state_listener") &&
      !this._checkClass("scanner_listener") &&
      !this._checkClass("scope_listener")
    ) {
      this.fs.delete(path.join(this.packageDestDir, "event_listeners"));
    }
  }

  _checkClass(className) {
    return this.props.classes[className] === true;
  }
};
