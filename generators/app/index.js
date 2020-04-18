const Generator = require("yeoman-generator");
const chalk = require("chalk");
const yosay = require("yosay");

module.exports = class extends Generator {
  initializing() {
    this.composeWith(require.resolve("generator-license"));
    this.composeWith("burp-extension:extension");
  }

  prompting() {
    this.log(yosay(`Welcome to the ${chalk.red("burp-extension")} generator!`));
  }
};
