#!/usr/bin/env python3
"""
Cryptographic performance benchmarking for GhostVault
Provides detailed analysis of encryption/decryption performance
"""

import time
import sys
import os
import statistics
from typing import Dict, List, Any
import crypto
import storage

def benchmark_argon2_performance(iterations: List[int] = [1, 2, 3, 4, 5]) -> Dict[str, Any]:
    """Benchmark Argon2 key derivation with different iteration counts"""
    print("🔐 Benchmarking Argon2 Key Derivation...")
    
    results = {}
    password = "TestPassword123!"
    salt = crypto.generate_salt()
    
    for iter_count in iterations:
        times = []
        for _ in range(5):  # 5 runs per iteration count
            start_time = time.time()
            crypto.derive_key(password, salt, iterations=iter_count)
            end_time = time.time()
            times.append(end_time - start_time)
        
        avg_time = statistics.mean(times)
        results[f"{iter_count}_iterations"] = {
            'average_time': avg_time,
            'min_time': min(times),
            'max_time': max(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0
        }
        print(f"  {iter_count} iterations: {avg_time:.4f}s avg")
    
    return results

def benchmark_encryption_performance(data_sizes: List[int] = [1024, 10240, 102400, 1048576]) -> Dict[str, Any]:
    """Benchmark AES-GCM encryption with different data sizes"""
    print("🔒 Benchmarking AES-GCM Encryption...")
    
    results = {}
    key = crypto.generate_salt(32)  # 32-byte key
    
    for size in data_sizes:
        data = os.urandom(size)
        times = []
        
        for _ in range(10):  # 10 runs per size
            start_time = time.time()
            crypto.encrypt_blob(key, data)
            end_time = time.time()
            times.append(end_time - start_time)
        
        avg_time = statistics.mean(times)
        throughput = size / avg_time / 1024 / 1024  # MB/s
        
        results[f"{size}_bytes"] = {
            'average_time': avg_time,
            'throughput_mbps': throughput,
            'min_time': min(times),
            'max_time': max(times)
        }
        print(f"  {size:,} bytes: {avg_time:.4f}s ({throughput:.2f} MB/s)")
    
    return results

def benchmark_full_vault_operations() -> Dict[str, Any]:
    """Benchmark complete vault creation and unlock operations"""
    print("🗄️ Benchmarking Full Vault Operations...")
    
    results = {}
    
    # Test vault creation
    create_times = []
    for i in range(3):
        start_time = time.time()
        try:
            vault_id = storage.create_vault_system(
                real_password=f"TestReal{i}!",
                panic_password=f"TestPanic{i}!",
                decoy_passwords=[f"TestDecoy1{i}!", f"TestDecoy2{i}!"],
                real_files=[],
                decoy_files=[[], []]
            )
            end_time = time.time()
            create_times.append(end_time - start_time)
            print(f"  Vault creation {i+1}: {end_time - start_time:.4f}s")
        except Exception as e:
            print(f"  Vault creation {i+1} failed: {e}")
    
    if create_times:
        results['vault_creation'] = {
            'average_time': statistics.mean(create_times),
            'min_time': min(create_times),
            'max_time': max(create_times)
        }
    
    # Test vault unlocking
    unlock_times = []
    for i in range(5):
        start_time = time.time()
        try:
            result = storage.attempt_unlock(f"TestReal0!")
            end_time = time.time()
            if result:
                unlock_times.append(end_time - start_time)
                print(f"  Vault unlock {i+1}: {end_time - start_time:.4f}s")
        except Exception as e:
            print(f"  Vault unlock {i+1} failed: {e}")
    
    if unlock_times:
        results['vault_unlock'] = {
            'average_time': statistics.mean(unlock_times),
            'min_time': min(unlock_times),
            'max_time': max(unlock_times)
        }
    
    return results

def memory_usage_analysis() -> Dict[str, Any]:
    """Analyze memory usage patterns"""
    print("💾 Analyzing Memory Usage...")
    
    try:
        import psutil
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Generate large data and encrypt
        large_data = os.urandom(10 * 1024 * 1024)  # 10MB
        key = crypto.generate_salt(32)
        
        before_encrypt = process.memory_info().rss / 1024 / 1024
        encrypted = crypto.encrypt_blob(key, large_data)
        after_encrypt = process.memory_info().rss / 1024 / 1024
        
        # Decrypt
        before_decrypt = process.memory_info().rss / 1024 / 1024
        decrypted = crypto.decrypt_blob(key, encrypted)
        after_decrypt = process.memory_info().rss / 1024 / 1024
        
        return {
            'initial_memory_mb': initial_memory,
            'memory_during_encryption_mb': after_encrypt,
            'memory_during_decryption_mb': after_decrypt,
            'encryption_memory_delta_mb': after_encrypt - before_encrypt,
            'decryption_memory_delta_mb': after_decrypt - before_decrypt
        }
    
    except ImportError:
        print("  psutil not available, skipping memory analysis")
        return {}

def security_timing_analysis() -> Dict[str, Any]:
    """Analyze timing characteristics for security assessment"""
    print("🔍 Security Timing Analysis...")
    
    results = {}
    
    # Test constant-time comparison
    data1 = b"correct_password_hash"
    data2 = b"incorrect_password!!"
    data3 = b"correct_password_hash"
    
    # Measure comparison times
    same_times = []
    diff_times = []
    
    for _ in range(1000):
        # Same data comparison
        start = time.perf_counter()
        crypto.secure_compare(data1, data3)
        end = time.perf_counter()
        same_times.append(end - start)
        
        # Different data comparison
        start = time.perf_counter()
        crypto.secure_compare(data1, data2)
        end = time.perf_counter()
        diff_times.append(end - start)
    
    results['timing_analysis'] = {
        'same_data_avg_ns': statistics.mean(same_times) * 1e9,
        'diff_data_avg_ns': statistics.mean(diff_times) * 1e9,
        'same_data_std_ns': statistics.stdev(same_times) * 1e9,
        'diff_data_std_ns': statistics.stdev(diff_times) * 1e9,
        'timing_consistent': abs(statistics.mean(same_times) - statistics.mean(diff_times)) < 1e-8
    }
    
    print(f"  Same data: {results['timing_analysis']['same_data_avg_ns']:.2f}ns avg")
    print(f"  Diff data: {results['timing_analysis']['diff_data_avg_ns']:.2f}ns avg")
    print(f"  Timing consistent: {results['timing_analysis']['timing_consistent']}")
    
    return results

def generate_comprehensive_report() -> Dict[str, Any]:
    """Generate a comprehensive performance and security report"""
    print("📊 Generating Comprehensive Benchmark Report...")
    print("=" * 60)
    
    report = {
        'timestamp': time.time(),
        'system_info': {
            'python_version': sys.version,
            'platform': sys.platform
        }
    }
    
    try:
        # Run all benchmarks
        report['argon2_benchmark'] = benchmark_argon2_performance()
        report['encryption_benchmark'] = benchmark_encryption_performance()
        report['vault_operations'] = benchmark_full_vault_operations()
        report['memory_analysis'] = memory_usage_analysis()
        report['security_timing'] = security_timing_analysis()
        
        print("=" * 60)
        print("✅ Benchmark complete! Summary:")
        print(f"🔐 Argon2 (3 iterations): ~{report['argon2_benchmark'].get('3_iterations', {}).get('average_time', 0):.3f}s")
        print(f"🔒 AES-GCM (1MB): ~{report['encryption_benchmark'].get('1048576_bytes', {}).get('throughput_mbps', 0):.1f} MB/s")
        
        if 'vault_creation' in report['vault_operations']:
            print(f"🗄️ Vault creation: ~{report['vault_operations']['vault_creation']['average_time']:.3f}s")
        
        if 'timing_consistent' in report.get('security_timing', {}).get('timing_analysis', {}):
            timing_ok = report['security_timing']['timing_analysis']['timing_consistent']
            print(f"🔍 Timing attack resistance: {'✅ PASS' if timing_ok else '❌ FAIL'}")
        
    except Exception as e:
        print(f"❌ Benchmark failed: {e}")
        report['error'] = str(e)
    
    return report

if __name__ == "__main__":
    report = generate_comprehensive_report()
    
    # Save detailed report
    import json
    with open('benchmark_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📁 Detailed report saved to: benchmark_report.json")