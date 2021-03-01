/*
 * Copyright 2016 the original author or authors.
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
package org.gradle.api.internal.changedetection.state;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.gradle.api.internal.cache.StringInterner;
import org.gradle.cache.PersistentIndexedCache;
import org.gradle.cache.PersistentIndexedCacheParameters;
import org.gradle.internal.file.FileMetadata;
import org.gradle.internal.hash.FileHasher;
import org.gradle.internal.hash.HashCode;
import org.gradle.internal.nativeintegration.filesystem.FileSystem;
import org.gradle.internal.serialize.AbstractSerializer;
import org.gradle.internal.serialize.Decoder;
import org.gradle.internal.serialize.Encoder;
import org.gradle.internal.serialize.HashCodeSerializer;
import org.gradle.internal.serialize.InterningStringSerializer;

import java.io.EOFException;
import java.io.File;
import java.util.Set;

public class CachingFileHasher implements FileHasher {
    private static final Set<String> NO_PATTERNS = ImmutableSet.of();

    private final PersistentIndexedCache<FileHashKey, FileInfo> cache;
    private final FileHasher delegate;
    private final FileSystem fileSystem;
    private final StringInterner stringInterner;
    private final FileTimeStampInspector timestampInspector;
    private final FileHasherStatistics.Collector statisticsCollector;
    private final Set<String> sourceFilePatterns;

    public CachingFileHasher(
        FileHasher delegate,
        CrossBuildFileHashCache store,
        StringInterner stringInterner,
        FileTimeStampInspector timestampInspector,
        String cacheName,
        FileSystem fileSystem,
        int inMemorySize,
        FileHasherStatistics.Collector statisticsCollector
    ) {
       this(delegate, store, stringInterner, timestampInspector, cacheName, fileSystem, inMemorySize, statisticsCollector, NO_PATTERNS);
    }

    public CachingFileHasher(
        FileHasher delegate,
        CrossBuildFileHashCache store,
        StringInterner stringInterner,
        FileTimeStampInspector timestampInspector,
        String cacheName,
        FileSystem fileSystem,
        int inMemorySize,
        FileHasherStatistics.Collector statisticsCollector,
        Set<String> sourceFilePatterns
    ) {
        this.delegate = delegate;
        this.fileSystem = fileSystem;
        this.cache = store.createCache(
            PersistentIndexedCacheParameters.of(cacheName, new FileHashKeySerializer(stringInterner), new FileInfoSerializer()),
            inMemorySize,
            true);
        this.stringInterner = stringInterner;
        this.timestampInspector = timestampInspector;
        this.statisticsCollector = statisticsCollector;
        this.sourceFilePatterns = sourceFilePatterns;
    }

    @Override
    public String toString() {
        return "{hasher cache: " + cache + "}";
    }

    @Override
    public HashCode hash(File file) {
        return snapshot(file).getHash();
    }

    @Override
    public HashCode hash(File file, long length, long lastModified) {
        return snapshot(file, length, lastModified).getHash();
    }

    private FileInfo snapshot(File file) {
        FileMetadata fileMetadata = fileSystem.stat(file);
        return snapshot(file, fileMetadata.getLength(), fileMetadata.getLastModified());
    }

    private FileInfo snapshot(File file, long length, long timestamp) {
        String absolutePath = file.getAbsolutePath();
        FileHashKey key = new FileHashKey(stringInterner.intern(absolutePath), sourceFilePatterns);
        if (timestampInspector.timestampCanBeUsedToDetectFileChange(absolutePath, timestamp)) {
            FileInfo info = cache.getIfPresent(key);

            if (info != null && length == info.length && timestamp == info.timestamp) {
                return info;
            }
        }

        HashCode hash = delegate.hash(file);
        FileInfo info = new FileInfo(hash, length, timestamp);
        cache.put(key, info);
        statisticsCollector.reportFileHashed(length);
        return info;
    }

    public void discard(String path) {
        cache.remove(new FileHashKey(path, sourceFilePatterns));
    }

    @VisibleForTesting
    static class FileHashKey {
        private final String path;
        private final Set<String> sourceFilePatterns;

        public FileHashKey(String path, Set<String> sourceFilePatterns) {
            this.path = path;
            this.sourceFilePatterns = sourceFilePatterns;
        }

        public String getPath() {
            return path;
        }

        public Set<String> getSourceFilePatterns() {
            return sourceFilePatterns;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            FileHashKey that = (FileHashKey) o;
            return path.equals(that.path) &&
                sourceFilePatterns.equals(that.sourceFilePatterns);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(path, sourceFilePatterns);
        }
    }

    @VisibleForTesting
    static class FileInfo {
        private final HashCode hash;
        private final long timestamp;
        private final long length;

        public FileInfo(HashCode hash, long length, long timestamp) {
            this.hash = hash;
            this.length = length;
            this.timestamp = timestamp;
        }

        public HashCode getHash() {
            return hash;
        }
    }

    private static class FileHashKeySerializer extends AbstractSerializer<FileHashKey> {
        private final InterningStringSerializer stringSerializer;

        public FileHashKeySerializer(StringInterner stringInterner) {
            this.stringSerializer = new InterningStringSerializer(stringInterner);
        }

        @Override
        public FileHashKey read(Decoder decoder) throws EOFException, Exception {
            String path = stringSerializer.read(decoder);
            int patternCount = decoder.readInt();
            Set<String> patterns;
            if (patternCount == 0) {
                patterns = NO_PATTERNS;
            } else {
                patterns = Sets.newHashSet();
                for (int i = 0; i < patternCount; i++) {
                    patterns.add(stringSerializer.read(decoder));
                }
            }
            return new FileHashKey(path, patterns);
        }

        @Override
        public void write(Encoder encoder, FileHashKey key) throws Exception {
            stringSerializer.write(encoder, key.getPath());

            Set<String> patterns = key.getSourceFilePatterns();
            encoder.writeInt(patterns.size());
            for (String pattern : patterns) {
                stringSerializer.write(encoder, pattern);
            }
        }
    }

    private static class FileInfoSerializer extends AbstractSerializer<FileInfo> {
        private final HashCodeSerializer hashCodeSerializer = new HashCodeSerializer();

        @Override
        public FileInfo read(Decoder decoder) throws Exception {
            HashCode hash = hashCodeSerializer.read(decoder);
            long timestamp = decoder.readLong();
            long length = decoder.readLong();
            return new FileInfo(hash, length, timestamp);
        }

        @Override
        public void write(Encoder encoder, FileInfo value) throws Exception {
            hashCodeSerializer.write(encoder, value.hash);
            encoder.writeLong(value.timestamp);
            encoder.writeLong(value.length);
        }

        @Override
        public boolean equals(Object obj) {
            if (!super.equals(obj)) {
                return false;
            }

            FileInfoSerializer rhs = (FileInfoSerializer) obj;
            return Objects.equal(hashCodeSerializer, rhs.hashCodeSerializer);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(super.hashCode(), hashCodeSerializer);
        }
    }
}
