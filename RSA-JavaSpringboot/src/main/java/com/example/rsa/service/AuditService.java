package com.example.rsa.service;

import com.example.rsa.model.AuditLog;
import com.example.rsa.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuditService {
    @Autowired
    private AuditLogRepository auditLogRepository;

    public void log(Long userId, String action, String details) {
        // VULNERABILITY 5 & 6: Incomplete logging and potentially sensitive data
        // logging
        auditLogRepository.save(new AuditLog(userId, action, details));
    }
}
