/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Apache License, Version 2.0 (the "License");
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

/**
 * Product classification of a project with digital elements under the
 * EU Cyber Resilience Act (Regulation (EU) 2024/2847), per CRA Art. 6 and
 * Annexes III-IV. Drives the conformity assessment route.
 *
 * @since 5.4.0
 */
public enum CraProductClass {

    /**
     * Product not listed in CRA Annexes III or IV. Self-certification
     * (Internal Control, Module A) is available.
     */
    DEFAULT,

    /**
     * Important product, Class I (CRA Annex III). Self-certification when a
     * harmonized standard is applied in full, otherwise notified body.
     */
    IMPORTANT_CLASS_I,

    /**
     * Important product, Class II (CRA Annex III). Notified body involvement
     * is mandatory.
     */
    IMPORTANT_CLASS_II,

    /**
     * Critical product (CRA Annex IV). European Cybersecurity Certification
     * Scheme or notified body assessment is mandatory.
     */
    CRITICAL,

    /**
     * The project has not yet been classified.
     */
    UNCLASSIFIED
}
