#!/usr/bin/env python

# Values can have two forms:
#
#   [NAME] [TYPE] [VALUE]
#   
#   [NAME] MULTILINE_OCTAL
#   [OCTAL]
#   END
#
# The file is divided into chunks that start with a value
# called CKA_CLASS, with one of three values:
#   CKO_NSS_BUILTIN_ROOT_LIST
#   CKO_CERTIFICATE
#   CKO_NSS_TRUST
#
# Parsing strategy
# * Strip comment lines /^#.*/ and blank lines
# * Split into objects at CKA_CLASS
# * Split into values

import re
import json
import sys
from base64 import b64encode, b64decode

def ignored(line):
  return re.search("^$", line) or re.search("^#", line) or re.search("^BEGINDATA$", line)

def valid_content(line):
  tokens = re.split("[ ]+", line)
  return (len(tokens) >= 3) or \
         ((len(tokens) == 2) and tokens[1] == "MULTILINE_OCTAL") or \
         ((len(tokens) == 1) and (tokens[0] in ["END", "BEGINDATA"] or \
                                  re.search("^[0-7\\\\]*$", tokens[0])))

def pop_token(string):
  tokens = re.split("[ ]+", string, 1)
  return (tokens[0], string[len(tokens[0]):].lstrip())

def octal_to_b64(o):
  return b64encode(o.decode("string_escape"))

def parse_certdata(source):
  lines = [line.rstrip() for line in source if not ignored(line)]

  # Check for lines that don't have the right syntax
  badlines = [line for line in lines if not valid_content(line)]
  if len(badlines) > 0:
    print >>sys.stderr, "Bad content"

  # Parse into objects
  objects = []
  curr_object = {}
  curr_value_name = ""
  multiline_buffer = ""
  in_multiline = False
  for line in lines:
    (token, rest) = pop_token(line)

    # Multi-line handling
    if token == "END":
      if not in_multiline:
        raise Exception("Invalid END line")
      curr_object[curr_value_name] = octal_to_b64(multiline_buffer)
      multiline_buffer = ""
      in_multiline = False;
      continue
    elif in_multiline:
      multiline_buffer += line
      continue

    # Start of a new object / end of the old
    if token == "CKA_CLASS":
      if len(curr_object) > 0:
        objects.append(curr_object)
      curr_object = {}

    (field, rest) = pop_token(line)
    (type_name, rest) = pop_token(rest)
    if type_name == "MULTILINE_OCTAL":
      in_multiline = True
      curr_value_name = field
    elif type_name == "UTF8":
      # Strip quotes
      curr_object[field] = rest[1:-1]
    else:
      curr_object[field] = rest
  if len(curr_object) > 0:
    objects.append(curr_object)

  # Merge trust data into the root object
  roots = {}
  for cert in [obj for obj in objects if obj["CKA_CLASS"] == "CKO_CERTIFICATE"]:
    roots[cert["CKA_LABEL"]] = cert
  for trust in [obj for obj in objects if obj["CKA_CLASS"] == "CKO_NSS_TRUST"]:
    label = trust["CKA_LABEL"]
    if label in roots:
      roots[label]["trust"] = {}
      for field in trust:
        if re.search("^CKA_TRUST_", field):
          roots[label]["trust"][field] = trust[field]

  # Check that each root got some trust
  untrusted = [label for label in roots if "trust" not in roots[label]]
  if len(untrusted) > 0:
    raise Exception("Some certs have no trust information: {}".format(repr(untrusted)))

  return roots


### BEGIN ###

# Parse the certdata.txt file
roots = parse_certdata(sys.stdin)
print >>sys.stderr, "Found {:d} roots overall".format(len(roots))

# Look for roots that can delegate for server auth
auth_roots = {}
for label in roots:
  if roots[label]["trust"]["CKA_TRUST_SERVER_AUTH"] == "CKT_NSS_TRUSTED_DELEGATOR":
    auth_roots[label] = roots[label]
print >>sys.stderr, "Found {:d} roots trusted for server auth".format(len(auth_roots))

# Generate a JSON struct representing the cert data
print json.dumps(roots, indent=2)

# Generate a python map of issuers -> labels
#print "{"
#for label in auth_roots:
#  issuer_hex = b64decode(auth_roots[label]["CKA_SUBJECT"]).encode("hex")
#  print '  # {}'.format(label)
#  print '  "{}": "{}",'.format(issuer_hex, label)
#print "}"

# Generate Go code for trusted issuers
#print "[][]byte{"
#for label in auth_roots:
#  issuer_hex = b64decode(auth_roots[label]["CKA_SUBJECT"]).encode("hex")
#  escaped = re.sub("(..)", "\\x\\1", issuer_hex);
#  print "  // {}".format(label)
#  print "  []byte(\"{}\"),".format(escaped)
#print "}"
