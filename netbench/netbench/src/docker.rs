// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize, Serialize, Hash)]
pub struct Compose {
    pub services: BTreeMap<String, Service>,
    pub configs: BTreeMap<String, Config>,
    pub networks: BTreeMap<String, Network>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Hash)]
pub struct Service {
    pub hostname: Option<String>,
    pub image: Option<String>,
    pub configs: Vec<String>,
    pub networks: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Hash)]
pub struct Config {
    pub file: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Hash)]
pub struct Network {
    pub driver: Option<String>,
}
