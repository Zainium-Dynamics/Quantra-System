use super::types::Service;
/// Service dependency resolution — topological sort + parallel wave computation
///
/// Provides two functions:
/// - `sort_services()` — flat ordered list (legacy, sequential startup)
/// - `wave_sort_services()` — BFS-level waves for parallel startup
///
/// A wave is a set of services with no mutual dependencies. Services within
/// the same wave can be started concurrently; the next wave begins only when
/// all services in the current wave have been launched.
///
/// # Algorithm: Kahn's BFS with level tracking
///
/// Classic Kahn's algorithm, extended to record which BFS "level" each node
/// is processed at. All nodes entering the queue in the same round belong
/// to the same wave.
use anyhow::Result;
use std::collections::{HashMap, VecDeque};

/// Sort services by dependency order (flat, sequential).
///
/// Returns `Err` if a circular dependency is detected.
#[inline]
#[allow(dead_code)] // Public API alias kept for external callers and integration tests
pub fn sort_services(services: &[Service]) -> Result<Vec<Service>> {
    Ok(wave_sort_services(services)?
        .into_iter()
        .flatten()
        .collect())
}

/// Sort services into BFS-level waves for parallel startup.
///
/// Each inner `Vec<Service>` is one wave — services within a wave have no
/// inter-dependencies and can be started concurrently.
///
/// Returns `Err` if a circular dependency is detected.
pub fn wave_sort_services(services: &[Service]) -> Result<Vec<Vec<Service>>> {
    if services.is_empty() {
        return Ok(Vec::new());
    }

    // Build service name → index map
    let name_to_idx: HashMap<&str, usize> = services
        .iter()
        .enumerate()
        .map(|(i, s)| (s.name.as_str(), i))
        .collect();

    let n = services.len();
    let mut in_degree = vec![0usize; n];
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

    // Edges: dependency/after → service (both `dependencies` and `after` impose ordering)
    for (idx, svc) in services.iter().enumerate() {
        for dep in svc.after.iter().chain(&svc.dependencies) {
            if let Some(&dep_idx) = name_to_idx.get(dep.as_str()) {
                adj[dep_idx].push(idx);
                in_degree[idx] += 1;
            }
            // Unknown dependencies are silently ignored (service may not be in config)
        }
    }

    // Kahn's BFS with wave-level tracking
    let mut queue: VecDeque<usize> = in_degree
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, d)| *d == 0)
        .map(|(i, _)| i)
        .collect();

    let mut waves: Vec<Vec<Service>> = Vec::new();
    let mut visited = 0usize;
    let mut degrees = in_degree; // shadow with mutable copy

    while !queue.is_empty() {
        // All nodes currently in the queue form one wave (same BFS level)
        let wave_size = queue.len();
        let mut wave = Vec::with_capacity(wave_size);

        for _ in 0..wave_size {
            let node = queue.pop_front().unwrap();
            wave.push(services[node].clone());
            visited += 1;

            for &neighbor in &adj[node] {
                degrees[neighbor] -= 1;
                if degrees[neighbor] == 0 {
                    queue.push_back(neighbor);
                }
            }
        }

        waves.push(wave);
    }

    if visited != n {
        // Identify services involved in the circular dependency
        let unresolved: Vec<&str> = services
            .iter()
            .enumerate()
            .filter(|(i, _)| degrees[*i] > 0)
            .map(|(_, svc)| svc.name.as_str())
            .collect();

        return Err(anyhow::anyhow!(
            "Circular dependency detected among services: [{}]. These services have unresolved dependencies that form a cycle ({} of {} resolved)",
            unresolved.join(", "),
            visited,
            n
        ));
    }

    log::info!(
        "Dependency resolution: {} services in {} parallel waves",
        n,
        waves.len()
    );

    Ok(waves)
}

#[cfg(test)]
mod tests {
    use super::wave_sort_services;
    use crate::services::types::Service;

    #[test]
    fn wave_sort_respects_dependencies() {
        let a = Service {
            name: "a".into(),
            command: "/bin/true".into(),
            ..Default::default()
        };

        let b = Service {
            name: "b".into(),
            command: "/bin/true".into(),
            dependencies: vec!["a".into()],
            ..Default::default()
        };

        let waves = wave_sort_services(&[a, b]).unwrap();

        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0][0].name, "a");
        assert_eq!(waves[1][0].name, "b");
    }
}
