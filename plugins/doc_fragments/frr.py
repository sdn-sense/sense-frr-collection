#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Wrapper to Documentation Module
Copyright: Contributors to the SENSE Project
GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

Title                   : sdn-sense/frr
Author                  : Justas Balcas
Email                   : juztas (at) gmail.com
@Copyright              : General Public License v3.0+
Date                    : 2023/12/11
"""
# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from ansible_collections.sense.frr.plugins.module_utils.runwrapper import \
    classwrapper


@classwrapper
class ModuleDocFragment:
    """Module Documentation Fragment"""

    DOCUMENTATION = ""
