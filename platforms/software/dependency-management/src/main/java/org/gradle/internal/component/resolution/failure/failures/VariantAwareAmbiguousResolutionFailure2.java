/*
 * Copyright 2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gradle.internal.component.resolution.failure.failures;

import org.gradle.api.internal.attributes.AttributeContainerInternal;
import org.gradle.api.internal.attributes.AttributesSchemaInternal;
import org.gradle.internal.component.model.ComponentGraphResolveMetadata;
import org.gradle.internal.component.resolution.failure.ResolutionCandidateAssessor;

import java.util.List;

public class VariantAwareAmbiguousResolutionFailure2 extends AmbiguousResolutionFailure2 {
    private final ComponentGraphResolveMetadata targetComponent;

    public VariantAwareAmbiguousResolutionFailure2(AttributesSchemaInternal schema, String requestedName, AttributeContainerInternal requestedAttributes, List<ResolutionCandidateAssessor.AssessedCandidate> candidates, ComponentGraphResolveMetadata targetComponent) {
        super(schema, requestedName, requestedAttributes, candidates);
        this.targetComponent = targetComponent;
    }

    public ComponentGraphResolveMetadata getTargetComponent() {
        return targetComponent;
    }
}
