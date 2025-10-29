#!/bin/bash

# 数据库文件路径
DB_FILE="frontend/tasks.db"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查数据库文件是否存在
if [ ! -f "$DB_FILE" ]; then
    echo -e "${RED}错误：数据库文件不存在${NC}"
    exit 1
fi

# 主菜单
show_menu() {
    echo -e "\n${BLUE}=========== 任务数据库查看器 ===========${NC}"
    echo "1. 查看所有任务列表"
    echo "2. 查看最新任务"
    echo "3. 查看特定任务详情"
    echo "4. 统计任务状态"
    echo "5. 查看任务结果"
    echo "6. 交互式 SQL 查询"
    echo "0. 退出"
    echo -e "${BLUE}========================================${NC}"
    echo -n "请选择: "
}

# 查看所有任务列表
view_all_tasks() {
    echo -e "\n${GREEN}=== 所有任务列表 ===${NC}"
    sqlite3 $DB_FILE -column -header "
    SELECT 
        substr(id, 1, 12) as '任务ID',
        status as '状态',
        datetime(created_time) as '创建时间',
        progress as '进度',
        CASE 
            WHEN results != '{}' AND results IS NOT NULL THEN '有结果'
            ELSE '无结果'
        END as '是否有结果'
    FROM tasks 
    ORDER BY created_time DESC"
}

# 查看最新任务
view_latest_task() {
    echo -e "\n${GREEN}=== 最新任务 ===${NC}"
    sqlite3 $DB_FILE -column -header "
    SELECT * FROM tasks ORDER BY created_time DESC LIMIT 1"
}

# 查看特定任务详情
view_task_detail() {
    echo -n "请输入任务ID（可以是部分ID）: "
    read task_id
    
    if [ -z "$task_id" ]; then
        echo -e "${RED}任务ID不能为空${NC}"
        return
    fi
    
    echo -e "\n${GREEN}=== 任务详情 ===${NC}"
    sqlite3 $DB_FILE -column -header "
    SELECT * FROM tasks WHERE id LIKE '%$task_id%'"
}

# 统计任务状态
view_task_stats() {
    echo -e "\n${GREEN}=== 任务状态统计 ===${NC}"
    sqlite3 $DB_FILE -column -header "
    SELECT 
        status as '状态',
        COUNT(*) as '数量'
    FROM tasks 
    GROUP BY status"
}

# 查看任务结果
view_task_results() {
    echo -n "请输入任务ID: "
    read task_id
    
    if [ -z "$task_id" ]; then
        echo -e "${RED}任务ID不能为空${NC}"
        return
    fi
    
    echo -e "\n${GREEN}=== 任务结果 ===${NC}"
    result=$(sqlite3 $DB_FILE "SELECT results FROM tasks WHERE id LIKE '%$task_id%'")
    
    if [ -z "$result" ]; then
        echo -e "${RED}未找到该任务${NC}"
        return
    fi
    
    echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result"
}

# 交互式 SQL 查询
interactive_sql() {
    echo -e "\n${GREEN}=== 交互式 SQL 查询 ===${NC}"
    echo "输入 SQL 查询语句（输入 quit 退出）"
    echo ""
    
    while true; do
        echo -n "${YELLOW}SQL> ${NC}"
        read sql_query
        
        if [ "$sql_query" = "quit" ] || [ "$sql_query" = "exit" ]; then
            break
        fi
        
        sqlite3 $DB_FILE -column -header "$sql_query" 2>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "${RED}SQL 执行错误${NC}"
        fi
    done
}

# 主循环
while true; do
    show_menu
    read choice
    
    case $choice in
        1) view_all_tasks ;;
        2) view_latest_task ;;
        3) view_task_detail ;;
        4) view_task_stats ;;
        5) view_task_results ;;
        6) interactive_sql ;;
        0) 
            echo -e "${BLUE}再见！${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            ;;
    esac
done

