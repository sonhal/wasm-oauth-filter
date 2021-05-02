
/// Test stubs
/// Implements the external function that is supplied by the WebAssembly host at startup
/// When compiling and running as x86_64 these external functions are not available and the program crashes
/// It is convenient to run unit tests as x86_64 as the testing support for WebAssembly is not mature.
#[cfg(test)]
#[allow(unused)]
pub mod overrides {
    use proxy_wasm::types::{Status, MapType, BufferType};

    #[no_mangle]
    pub extern "C" fn proxy_done() -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_http_call(
        upstream_data: *const u8,
        upstream_size: usize,
        headers_data: *const u8,
        headers_size: usize,
        body_data: *const u8,
        body_size: usize,
        trailers_data: *const u8,
        trailers_size: usize,
        timeout: u32,
        return_token: *mut u32,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_enqueue_shared_queue(
        queue_id: u32,
        value_data: *const u8,
        value_size: usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_dequeue_shared_queue(
        queue_id: u32,
        return_value_data: *mut *mut u8,
        return_value_size: *mut usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_register_shared_queue(
        name_data: *const u8,
        name_size: usize,
        return_id: *mut u32,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_set_property(
        path_data: *const u8,
        path_size: usize,
        value_data: *const u8,
        value_size: usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_resolve_shared_queue(
        vm_id_data: *const u8,
        vm_id_size: usize,
        name_data: *const u8,
        name_size: usize,
        return_id: *mut u32,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_get_property(
        path_data: *const u8,
        path_size: usize,
        return_value_data: *mut *mut u8,
        return_value_size: *mut usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_get_header_map_pairs(
        map_type: MapType,
        return_map_data: *mut *mut u8,
        return_map_size: *mut usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_get_buffer_bytes(
        buffer_type: BufferType,
        start: usize,
        max_size: usize,
        return_buffer_data: *mut *mut u8,
        return_buffer_size: *mut usize,
    ) -> Status {
        Status::Ok
    }

    #[no_mangle]
    pub extern "C" fn proxy_get_current_time_nanoseconds(return_time: *mut u64) -> Status {
        Status::Ok
    }

}