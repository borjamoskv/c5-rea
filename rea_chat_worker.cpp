// Native inference worker. JSON-lines carries requests and individual native
// steps; no reference connection, generated answers or application prompts.
#include "llama.h"
#include "ggml-backend.h"
#include "json.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <memory>

extern "C" int64_t c5_render(const char *, const char *, char *, uint64_t);
using json = nlohmann::ordered_json;

static void emit(const json & value) { std::cout << value.dump() << std::endl; }

struct Session {
    llama_context * context = nullptr;
    llama_sampler * sampler = nullptr;
    std::vector<llama_token> tokens;
    int count=0, limit=0, sampled=0, calls=0;
    llama_token previous=-1;
    bool prepared=false, started=false;
    ~Session() { if (sampler) llama_sampler_free(sampler); if (context) llama_free(context); }
};

int main() {
    llama_model * model = nullptr;
    std::map<std::string,std::unique_ptr<Session>> sessions;
    try {
        std::string line;
        if (!std::getline(std::cin, line)) return 1;
        auto config = json::parse(line);
        ggml_backend_load_all_from_path(config.at("runtime_directory").get<std::string>().c_str());
        llama_backend_init();
        auto mp = llama_model_default_params();
        mp.n_gpu_layers = config.at("gpu_layers").get<int>();
        mp.use_extra_bufts = false;
        mp.load_mode = LLAMA_LOAD_MODE_MMAP;
        mp.vocab_only = false;
        mp.no_alloc = false;
        model = llama_model_load_from_file(config.at("model_path").get<std::string>().c_str(), mp);
        if (!model) throw std::runtime_error("MODEL_LOAD_FAILED");
        auto cp = llama_context_default_params();
        cp.n_ctx = config.at("context_length").get<uint32_t>();
        cp.n_batch = 256; cp.n_ubatch = 64; cp.n_seq_max = 1;
        cp.n_threads = 6; cp.n_threads_batch = 6;
        cp.flash_attn_type = LLAMA_FLASH_ATTN_TYPE_ENABLED;
        if (config.at("gpu_layers").get<int>() == 0) {
            cp.offload_kqv = false; cp.op_offload = false;
        }
        auto vocab = llama_model_get_vocab(model);
        const char * tmpl = llama_model_chat_template(model, nullptr);
        if (!tmpl) throw std::runtime_error("MODEL_CHAT_TEMPLATE_MISSING");
        emit({{"ready",true},{"model_parameters",llama_model_n_params(model)},{"template",tmpl}});
        while (std::getline(std::cin, line)) {
            try {
                const auto message = json::parse(line);
                const std::string action = message.at("action");
                if (action == "shutdown") { emit({{"closed",true}}); break; }
                const std::string id = message.at("session");
                if (action == "release") { sessions.erase(id); emit({{"released",true}}); continue; }
                if (action == "prepare") {
                    if (sessions.count(id) || sessions.size() >= 4) throw std::runtime_error("SESSION_LIMIT");
                    auto fresh=std::make_unique<Session>();
                    fresh->context=llama_init_from_model(model,cp);
                    if (!fresh->context) throw std::runtime_error("CONTEXT_LOAD_FAILED");
                    sessions[id]=std::move(fresh);
                }
                if (!sessions.count(id)) throw std::runtime_error("UNKNOWN_SESSION");
                auto & state=*sessions.at(id);
                auto & context=state.context; auto & sampler=state.sampler; auto & tokens=state.tokens;
                auto & count=state.count; auto & limit=state.limit; auto & sampled=state.sampled; auto & calls=state.calls;
                auto & previous=state.previous; auto & prepared=state.prepared; auto & started=state.started;
                auto usage = [&]() { return json{{"prompt_tokens",count},{"completion_tokens",sampled},
                    {"total_tokens",count+sampled},{"completion_tokens_details",{{"reasoning_tokens",0}}}}; };
                std::cerr << json{{"event","native_step"},{"session",id},{"action",action},{"active_sessions",sessions.size()}}.dump() << std::endl;
                if (action == "prepare") {
                    const auto request = message.at("request");
                    limit = request.at("max_tokens").get<int>();
                    if (limit < 1 || limit > 256 || request.at("repeat_penalty") != 1)
                        throw std::runtime_error("UNSUPPORTED_SAMPLING");
                    float temperature=request.at("temperature").get<float>();
                    if (temperature < 0 || temperature > 2) throw std::runtime_error("TEMPERATURE_OUT_OF_SCOPE");
                    if (temperature == 0) sampler=llama_sampler_init_greedy();
                    else {
                        sampler=llama_sampler_chain_init(llama_sampler_chain_default_params());
                        llama_sampler_chain_add(sampler,llama_sampler_init_top_k(request.value("top_k",40)));
                        llama_sampler_chain_add(sampler,llama_sampler_init_top_p(request.value("top_p",0.95f),1));
                        llama_sampler_chain_add(sampler,llama_sampler_init_min_p(request.value("min_p",0.05f),1));
                        llama_sampler_chain_add(sampler,llama_sampler_init_temp(temperature));
                        llama_sampler_chain_add(sampler,llama_sampler_init_dist(request.at("seed").get<uint32_t>()));
                    }
                    json history=request.at("messages");
                    for (auto & m:history) if (m.contains("tool_calls")) for (auto & t:m["tool_calls"])
                        if (t["function"]["arguments"].is_string()) t["function"]["arguments"]=json::parse(t["function"]["arguments"].get<std::string>());
                    json variables = {{"messages",history},{"add_generation_prompt",true},
                        {"tools",request.value("tools",json(nullptr))},{"bos_token",""},{"eos_token",""}};
                    std::string input = variables.dump();
                    std::vector<char> rendered(std::max<size_t>(4096,input.size()*4));
                    auto size = c5_render(tmpl,input.c_str(),rendered.data(),rendered.size());
                    if (size >= static_cast<int64_t>(rendered.size()) && size < 1048576) {
                        rendered.resize(size+1);
                        size = c5_render(tmpl,input.c_str(),rendered.data(),rendered.size());
                    }
                    if (size < 0 || size >= static_cast<int64_t>(rendered.size())) throw std::runtime_error("CHAT_TEMPLATE_FAILED");
                    tokens.resize(size+32);
                    count = llama_tokenize(vocab,rendered.data(),size,tokens.data(),tokens.size(),true,true);
                    if (count <= 0 || count+limit > static_cast<int>(cp.n_ctx)) throw std::runtime_error("CONTEXT_LIMIT_EXCEEDED");
                    tokens.resize(count);
                    sampled=0; calls=0; previous=-1; started=false; prepared=true;
                    emit({{"prepared",true},{"prompt_tokens",count}});
                } else if (action == "step") {
                    if (!prepared) throw std::runtime_error("NO_PREPARED_REQUEST");
                    if (!started) {
                        llama_memory_clear(llama_get_memory(context),true);
                        if (llama_decode(context,llama_batch_get_one(tokens.data(),count)) != 0) throw std::runtime_error("PREFILL_FAILED");
                        calls=1; started=true;
                    } else if (previous >= 0) {
                        if (llama_decode(context,llama_batch_get_one(&previous,1)) != 0) throw std::runtime_error("DECODE_FAILED");
                        ++calls; previous=-1;
                    }
                    if (sampled >= limit) {
                        prepared=false; emit({{"finish_reason","length"},{"usage",usage()},{"native_calls",calls}});
                        continue;
                    }
                    auto token = llama_sampler_sample(sampler,context,-1);
                    ++sampled;
                    if (llama_vocab_is_eog(vocab,token)) {
                        prepared=false; emit({{"finish_reason","stop"},{"usage",usage()},{"native_calls",calls}});
                        continue;
                    }
                    std::vector<char> piece(16384);
                    int size = llama_token_to_piece(vocab,token,piece.data(),piece.size(),0,true);
                    if (size < 0 || size > static_cast<int>(piece.size())) throw std::runtime_error("TOKEN_PIECE_TOO_LARGE");
                    std::string hex; const char * digits="0123456789abcdef";
                    for (int i=0;i<size;++i) { auto b=static_cast<unsigned char>(piece[i]); hex+=digits[b>>4]; hex+=digits[b&15]; }
                    previous=token;
                    emit({{"piece_hex",hex},{"native_calls",calls}});
                } else if (action == "stop") {
                    if (!prepared) throw std::runtime_error("NO_PREPARED_REQUEST");
                    prepared=false;
                    emit({{"finish_reason","stop"},{"usage",usage()},{"native_calls",calls}});
                } else throw std::runtime_error("UNKNOWN_NATIVE_ACTION");
            } catch (const std::exception & error) { emit({{"error",error.what()}}); }
        }
        sessions.clear();
        llama_model_free(model); model=nullptr;
        llama_backend_free();
        return 0;
    } catch (const std::exception & error) {
        std::cerr << "NATIVE_WORKER_FAILED: " << error.what() << std::endl;
        sessions.clear();
        if (model) llama_model_free(model);
        llama_backend_free();
        return 1;
    }
}
