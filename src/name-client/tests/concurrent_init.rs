use name_client::*;
use std::sync::Arc;
use tokio::sync::Barrier;

//回归测试：并发首次调用 init_name_lib 时，输掉 IS_NAME_LIB_INITED.set 竞争的一方曾直接 panic。
//必须放在独立的集成测试二进制中，保证运行时全局 OnceCell 尚未初始化。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_init_name_lib_does_not_panic() {
    let web3_config = get_default_web3_bridge_config();
    let task_count = 8;
    let barrier = Arc::new(Barrier::new(task_count));

    let mut handles = Vec::with_capacity(task_count);
    for _ in 0..task_count {
        let web3_config = web3_config.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            init_name_lib_for_test(&web3_config).await
        }));
    }

    for handle in handles {
        handle
            .await
            .expect("init_name_lib task panicked")
            .expect("init_name_lib returned error");
    }

    assert!(GLOBAL_NAME_CLIENT.get().is_some());
    assert_eq!(IS_NAME_LIB_INITED.get(), Some(&true));

    //初始化完成后再次调用仍应幂等成功
    init_name_lib_for_test(&web3_config).await.unwrap();
}
