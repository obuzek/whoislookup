#!/bin/bash

grep -P "University|Institute" whoisCache/* | grep -oP "\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?" >> whitelist
