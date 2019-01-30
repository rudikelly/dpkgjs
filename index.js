'use strict';

const os = require('os');
const fs = require('fs');
const path = require('path');
const ar = require('ar');
const tar = require('tar');
const crypto = require('crypto');
const stream = require('stream');

class dpkg {

  /**
   * Performs similar operation to dpkg-scanpackages.
   *
   * @param  {string} dir - Directory to scan
   * @return {array}        Array of key/value pairs from control files
   * @public
   */
  static scanDir(dir, callback) {
    var packages = [];
    fs.readdir(dir, (err, files) => {
      if (err) throw err;
      const debs = files.filter(file => file.match(/.*\.deb/));
      var count = 0;
      for (let i = 0; i < debs.length; i++) {
        const deb = debs[i];
        const debPath = path.join(dir, deb);
        this.getControl(debPath, controlData => {
          packages.push(controlData);
          count++;
          if (count == debs.length) {
            callback(packages);
          }
        });
      }
    });
  }

  /**
   * Grabs a .deb file's control file and adds other useful data.
   *
   * @param  {string} debPath - Path to the .deb file
   * @return {array}            Parsed control file
   * @public
   */
  static getControl(debPath, callback) {
    fs.readFile(debPath, (err, data) => {
      if (err) throw err;
      var control = '';
      const controlArchive = new ar.Archive(data)
        .getFiles()
        .filter(file => file.name() === 'control.tar.gz')[0];
      var controlStream = new stream.Duplex();
      controlStream.push(controlArchive.fileData());
      controlStream.push(null);
      controlStream.pipe(
        tar.x({cwd: os.tmpdir()}, ))
        .on('entry', entry => {
          if (entry.path == './control') {
            control = entry.buffer.head.value.toString();
          }
        })
        .on('end', () => {
          if (!control) {
            throw new Error('Failed to find control file');
          }
          this.parseControl(control, parsedControl => {
            this.generateHashes(data, hashes => {
              const finalControl = Object.assign({}, parsedControl, hashes);
              fs.stat(debPath, (err, stats) => {
                finalControl['Size'] = stats.size;
                finalControl['Filename'] = debPath;
                callback(finalControl);
              });
            });
          });
        });
    });
  }

  static getControlFromFile(file, callback) {
    var control = '';
    const controlArchive = new ar.Archive(data)
      .getFiles()
      .filter(file => file.name() === 'control.tar.gz')[0];
    var controlStream = new stream.Duplex();
    controlStream.push(controlArchive.fileData());
    controlStream.push(null);
    controlStream.pipe(
      tar.x({cwd: os.tmpdir()}, ))
      .on('entry', entry => {
        if (entry.path == './control') {
          control = entry.buffer.head.value.toString();
        }
      })
      .on('end', () => {
        if (!control) {
          throw new Error('Failed to find control file');
        }
        this.parseControl(control, parsedControl => {
          this.generateHashes(data, hashes => {
            const finalControl = Object.assign({}, parsedControl, hashes);
            callback(finalControl);
          });
        });
      });
    }
  }

  /**
   * Parses a raw control file.
   *
   * @param  {string} control - Raw control file to parse
   * @return {object}           Parsed control file
   * @public
   */
  static parseControl(control, callback) {
    var controlData = {};

    const regex = {
      comment: /^#.*$/,
      field: /^([^\cA-\cZ\s:]+):\s*(.*)$/,
      continuation: /^(\s+)(.*)$/,
    };

    for (let line of control.split('\n')) {
      if (regex.comment.test(line)) {
        continue;
      }
      if (regex.continuation.test(line)) {
        controlData[previous] += '\n' + line.trim();
        continue;
      }
      var matches = regex.field.exec(line);
      if (matches) {
        const field = matches[1];
        const value = matches[2];
        controlData[field] = value;
        var previous = field;
      }
    }
    callback(controlData);
  }

  /**
   * Generates hashes for passed data.
   *
   * @param  {string} data - Data to hash
   * @return {array}         Array of hashes
   * @public
   */
  static generateHashes(data, callback) {
    var hashes = [];
    const md5 = crypto.createHash('md5');
    const sha1 = crypto.createHash('sha1');
    const sha256 = crypto.createHash('sha256');
    hashes['MD5Sum'] = md5.update(data).digest('hex');
    hashes['SHA1'] = sha1.update(data).digest('hex');
    hashes['SHA256'] = sha256.update(data).digest('hex');
    callback(hashes);
  }
}

module.exports = dpkg;
