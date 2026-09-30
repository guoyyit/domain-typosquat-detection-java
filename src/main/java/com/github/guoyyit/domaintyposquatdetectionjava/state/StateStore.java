package com.github.guoyyit.domaintyposquatdetectionjava.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/**
 * JSON 文件持久化：写入同目录临时文件后原子 move 替换正式文件。
 * 写入中途崩溃只会留下上一个完整版本（move 未发生）或完整新版本，
 * 不会出现部分生效的状态。
 */
@Component
public class StateStore {

    private static final Logger log = LoggerFactory.getLogger(StateStore.class);
    private static final String FILE_NAME = "state.json";
    private static final String TMP_SUFFIX = ".tmp";

    private final DetectionProperties properties;
    private final ObjectMapper objectMapper;

    public StateStore(DetectionProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public AppState load() {
        Path file = stateFile();
        if (!Files.exists(file)) {
            log.info("state file {} does not exist, starting empty", file);
            return new AppState();
        }
        try {
            AppState state = objectMapper.readValue(file.toFile(), AppState.class);
            if (state == null) {
                return new AppState();
            }
            log.info("loaded state from {} (version={})", file, state.getVersion());
            return state;
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read state file: " + file, e);
        }
    }

    public void save(AppState state) {
        Path file = stateFile();
        Path directory = file.getParent();
        Path tmp = directory.resolve(FILE_NAME + "." + Thread.currentThread().getId()
                + "." + System.nanoTime() + TMP_SUFFIX);
        try {
            Files.createDirectories(directory);
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), state);
            restrictIfPosix(tmp);
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            deleteQuietly(tmp);
            throw new UncheckedIOException("failed to persist state to " + file, e);
        }
    }

    public Path stateFile() {
        return Path.of(properties.getPersistence().getDir()).resolve(FILE_NAME);
    }

    private void restrictIfPosix(Path path) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, perms);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows 等非 POSIX 文件系统跳过
        }
    }

    private void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            log.debug("could not delete temp file {}", path);
        }
    }
}
