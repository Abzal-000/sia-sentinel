import sys
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from sia.dashboard_data import (
    build_agent_graph_dot,
    build_ast_dot,
    calculate_kpis,
    events_to_dataframe,
    get_change_proposals,
    get_failure_analysis,
    get_task_summary,
    get_trust_level_history,
    load_events,
    load_traces,
    traces_to_dataframe,
)

st.set_page_config(page_title="SIA Dashboard", layout="wide")
st.title("Self-Improving Agent Dashboard")

LOG_DIR = "logs"

# Размер окна ленивой загрузки событий (аудит: не грузить всю историю сразу)
EVENT_WINDOW_STEP = 200


@st.cache_data(ttl=5)
def get_data(limit: int):
    events = load_events(LOG_DIR, limit=limit)
    df = events_to_dataframe(events)
    return df


@st.cache_data(ttl=5)
def get_trace_data():
    traces = load_traces(LOG_DIR)
    df = traces_to_dataframe(traces)
    return df


if "event_limit" not in st.session_state:
    st.session_state.event_limit = EVENT_WINDOW_STEP

df = get_data(st.session_state.event_limit)
trace_df = get_trace_data()

if df.empty:
    st.info("Нет данных. Запустите задачи через CLI, чтобы увидеть статистику.")
    st.stop()

kpis = calculate_kpis(df)

# === KPI Section ===
st.subheader("Ключевые метрики")
col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

col1.metric("Всего задач", kpis["total_tasks"])
col2.metric("Одобрено", kpis["approved_tasks"])
col3.metric("Отклонено", kpis["rejected_tasks"])
col4.metric(
    "Средний Safety Score",
    f"{kpis['avg_safety_score']:.2f}" if kpis["avg_safety_score"] is not None else "N/A",
)
col5.metric(
    "Средний Performance Gain",
    f"{kpis['avg_performance_gain']:.2%}" if kpis["avg_performance_gain"] is not None else "N/A",
)
col6.metric(
    "Overall Efficiency Score",
    f"{kpis['avg_overall_efficiency_score']:.2f}" if kpis["avg_overall_efficiency_score"] is not None else "N/A",
)
col7.metric(
    "Проверенная экономия",
    f"${kpis['total_verified_savings_usd']:.4f}" if kpis.get("total_verified_savings_usd") is not None else "N/A",
)

# === Tabs ===
tab_tasks, tab_graph, tab_traces, tab_failures, tab_trust, tab_logs = st.tabs(
    ["История задач", "Граф агента", "Трейсы", "Анализ отказов", "Уровень доверия", "Логи"]
)

# === Tab 1: Task History (lazy loading) ===
with tab_tasks:
    st.subheader("История задач")

    if st.button("Загрузить ещё", help=f"Показать на {EVENT_WINDOW_STEP} событий больше"):
        st.session_state.event_limit += EVENT_WINDOW_STEP
        st.rerun()

    st.caption(
        f"Показаны последние {st.session_state.event_limit} событий "
        "(ленивая загрузка, полная история не парсится)."
    )

    task_summary = get_task_summary(df)

    if not task_summary.empty:
        status_filter = st.multiselect(
            "Фильтр по статусу:",
            options=task_summary["status"].unique().tolist(),
            default=task_summary["status"].unique().tolist(),
        )
        filtered = task_summary[task_summary["status"].isin(status_filter)]
        st.dataframe(filtered, use_container_width=True)
    else:
        st.write("Нет информации о задачах.")

# === Tab 2: Agent Graph & AST ===
with tab_graph:
    st.subheader("Граф выполнения агента")

    task_ids = df[df["event_type"] == "task_received"]["payload"].apply(
        lambda payload: payload.get("task_id") if isinstance(payload, dict) else None
    ).dropna().tolist()

    if task_ids:
        selected_graph_task = st.selectbox(
            "Задача для графа:",
            options=list(reversed(task_ids)),
        )
        st.graphviz_chart(build_agent_graph_dot(df, task_id=selected_graph_task))
    else:
        st.write("Нет задач для построения графа.")

    st.subheader("Визуализация AST предложенного кода")

    proposals = get_change_proposals(df)

    if proposals:
        options = [
            f"{proposal['task_id'][:8]}… ({proposal['model_name'] or 'модель неизвестна'})"
            for proposal in proposals
        ]
        selected_index = st.selectbox("Предложение кода:", options=range(len(proposals)), format_func=lambda i: options[i])
        st.graphviz_chart(build_ast_dot(proposals[selected_index]["new_code"]))

        with st.expander("Исходный код предложения"):
            st.code(proposals[selected_index]["new_code"], language="python")
    else:
        st.info("Нет предложений кода в логах для построения AST.")

# === Tab 2: Traces ===
with tab_traces:
    st.subheader("Визуализация трейсов")

    if trace_df.empty:
        st.info(
            "Нет данных трейсов. Запустите CLI с флагом `--enable-tracing` "
            "и `--tracing-exporter both`, чтобы сохранить трейсы в `logs/traces.jsonl`."
        )
    else:
        # Фильтр по trace_id
        trace_ids = trace_df["trace_id"].unique().tolist()
        selected_trace = st.selectbox("Выберите trace_id:", options=trace_ids)

        if selected_trace:
            trace_spans = trace_df[trace_df["trace_id"] == selected_trace].copy()

            # Timeline chart
            st.subheader("Timeline выполнения")

            chart_data = trace_spans[["name", "duration_ms"]].copy()
            chart_data = chart_data.sort_values("duration_ms", ascending=False)

            st.bar_chart(chart_data.set_index("name")["duration_ms"])

            # Detailed table
            st.subheader("Детали спанов")
            st.dataframe(
                trace_spans[["name", "duration_ms", "attributes"]],
                use_container_width=True,
            )

# === Tab 3: Failure Analysis ===
with tab_failures:
    st.subheader("Анализ причин отказов")

    failure_df = get_failure_analysis(df)

    if failure_df.empty:
        st.success("Отказов не зафиксировано. Все задачи выполнены успешно!")
    else:
        # Summary by category
        st.subheader("Отказы по категориям")
        category_counts = failure_df["category"].value_counts()
        st.bar_chart(category_counts)

        # Detailed table
        st.subheader("Детали отказов")
        st.dataframe(failure_df, use_container_width=True)

# === Tab 4: Trust Level History ===
with tab_trust:
    st.subheader("Уровень доверия")
    trust_history = get_trust_level_history(df)

    if not trust_history.empty:
        level_order = ["NOVICE", "INTERN", "JUNIOR", "MID", "SENIOR"]
        trust_history["level_num"] = trust_history["level"].apply(
            lambda x: level_order.index(x) if x in level_order else 0
        )
        st.line_chart(trust_history.set_index("datetime")["level_num"])
    else:
        st.write("Нет истории изменения уровня доверия.")

# === Tab 5: Logs ===
with tab_logs:
    st.subheader("Логи событий")

    event_types = df["event_type"].unique().tolist()
    selected_types = st.multiselect(
        "Фильтр по типу события:",
        options=event_types,
        default=event_types,
    )

    last_events = df[df["event_type"].isin(selected_types)].tail(100).sort_values("timestamp", ascending=False)
    st.dataframe(
        last_events[["datetime", "event_type", "payload"]],
        use_container_width=True,
    )
