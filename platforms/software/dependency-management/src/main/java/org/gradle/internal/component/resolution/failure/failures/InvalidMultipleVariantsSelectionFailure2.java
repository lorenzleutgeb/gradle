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

import com.google.common.collect.ImmutableList;
import org.gradle.api.internal.attributes.AttributesSchemaInternal;
import org.gradle.internal.component.resolution.failure.ResolutionCandidateAssessor.AssessedCandidate;

import java.util.List;

public class InvalidMultipleVariantsSelectionFailure2 extends ResolutionFailure2 {
    private final ImmutableList<AssessedCandidate> assessedCandidates;

    public InvalidMultipleVariantsSelectionFailure2(AttributesSchemaInternal schema, String requestedName, List<AssessedCandidate> assessedCandidates) {
        super(schema, requestedName);
        this.assessedCandidates = ImmutableList.copyOf(assessedCandidates);
    }

    public ImmutableList<AssessedCandidate> getAssessedCandidates() {
        return assessedCandidates;
    }
}
