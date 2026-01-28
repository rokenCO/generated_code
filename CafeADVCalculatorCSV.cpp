/******************************************************************************
 * CafeADVCalculator CSV Support Implementation
 *****************************************************************************/

#include "CafeADVCalculatorCSV.h"
#include "CafeADVWorker.h"
#include "CSVParser.h"

#include <fstream>
#include <algorithm>
#include <cmath>

namespace volt::analysis {

/******************************************************************************
 * CSV Mode Constructor
 *****************************************************************************/
CafeADVCalculator::CafeADVCalculator(
    const std::string& csvPath,
    MessageDeliveryService* mds,
    staticdata::InstrumentStaticSource* staticDataSource,
    TimeManager* timeManager,
    std::shared_ptr<db::AsyncDbPool> asyncDbPool,
    FLog flog)
    : _mds(mds)
    , _staticDataSource(staticDataSource)
    , _timeManager(timeManager)
    , _asyncDbPool(asyncDbPool)
    , _flog(FLog(parent: flog, tag: StringStr() << "CafeADVCalc_CSV/"))
    , _csvMode(true)
{
    FLOG_INFORMATION(_flog, StringStr() << "Initializing CafeADVCalculator in CSV mode from: " << csvPath);
    
    if (!loadCSV(csvPath)) {
        FLOG_URGENT_ERROR(_flog, StringStr() << "Failed to load CSV file: " << csvPath 
            << " - all requests will fall back to DB");
    }
    
    FLOG_INFORMATION(_flog, StringStr() 
        << "CafeADVCalculator initialized: " << _csvCache.size() << " entries loaded"
        << ", date: " << _csvDate);
}

/******************************************************************************
 * Original DB Mode Constructor
 *****************************************************************************/
CafeADVCalculator::CafeADVCalculator(
    MessageDeliveryService* mds,
    staticdata::InstrumentStaticSource* staticDataSource,
    TimeManager* timeManager,
    std::shared_ptr<db::AsyncDbPool> asyncDbPool,
    FLog flog)
    : _mds(mds)
    , _staticDataSource(staticDataSource)
    , _timeManager(timeManager)
    , _asyncDbPool(asyncDbPool)
    , _flog(FLog(parent: flog, tag: StringStr() << "CafeADVCalc_DB/"))
    , _csvMode(false)
{
    FLOG_INFORMATION(_flog, StringStr() << "Initializing CafeADVCalculator in DB mode");
}

/******************************************************************************
 * Load CSV File
 * 
 * Expected format (header + data rows):
 * ric,scope,date,daily_volume,opening_volume,closing_volume,avg_trade_size,avg_continuous_trade_size,special_day_multiplier
 * AAPL.O,PRIMARY,2025-01-24,1000000.0,50000.0,75000.0,150.5,145.2,1.0
 *****************************************************************************/
bool CafeADVCalculator::loadCSV(const std::string& csvPath) {
    std::ifstream file(csvPath);
    if (!file.is_open()) {
        FLOG_URGENT_ERROR(_flog, StringStr() << "Cannot open CSV file: " << csvPath);
        return false;
    }
    
    std::string line;
    
    // Skip header line
    if (!std::getline(file, line)) {
        FLOG_URGENT_ERROR(_flog, StringStr() << "CSV file is empty: " << csvPath);
        return false;
    }
    
    size_t lineNum = 1;
    size_t loaded = 0;
    size_t errors = 0;
    
    while (std::getline(file, line)) {
        ++lineNum;
        
        // Skip empty lines
        if (line.empty()) {
            continue;
        }
        
        auto result = parseCSVLine(line);
        if (!result) {
            FLOG_WARNING(_flog, StringStr() << "Failed to parse CSV line " << lineNum << ": " << line);
            ++errors;
            continue;
        }
        
        auto& [key, entry] = *result;
        
        // Store date from first entry
        if (loaded == 0) {
            _csvDate = entry.date;
        }
        
        _csvCache[key] = std::move(entry);
        ++loaded;
    }
    
    FLOG_INFORMATION(_flog, StringStr() 
        << "CSV loading complete: " << loaded << " entries, " << errors << " errors");
    
    return loaded > 0;
}

/******************************************************************************
 * Parse Single CSV Line using volt::CSVParser
 * 
 * Format: ric,scope,date,daily_volume,opening_volume,closing_volume,avg_trade_size,avg_continuous_trade_size,special_day_multiplier
 * Index:   0    1     2        3              4              5             6                    7                       8
 *****************************************************************************/
std::optional<std::pair<CafeADVCalculator::CacheKey, CafeADVCalculator::CachedADVEntry>> 
CafeADVCalculator::parseCSVLine(const std::string& line) {
    volt::CSVParser parser;
    parser.parse(line);
    
    // Need at least 8 columns (special_day_multiplier is optional)
    if (parser.getCount() < 8) {
        return std::nullopt;
    }
    
    CacheKey key;
    CachedADVEntry entry;
    
    // 0: RIC
    key.ric = parser[0];
    if (key.ric.empty()) {
        return std::nullopt;
    }
    
    // 1: Scope (PRIMARY or CONS)
    std::string scopeStr = parser[1];
    if (scopeStr == "PRIMARY" || scopeStr == "PRIM") {
        key.scope = ADVScope::PRIMARY;
    } else if (scopeStr == "CONS" || scopeStr == "CONSOLIDATED") {
        key.scope = ADVScope::CONS;
    } else {
        return std::nullopt;
    }
    
    // 2: Date (YYYY-MM-DD or YYYY.MM.DD)
    std::string dateStr = parser[2];
    std::replace(dateStr.begin(), dateStr.end(), '.', '-');
    entry.date = Date::parse(dateStr);
    if (entry.date.isNull()) {
        return std::nullopt;
    }
    
    // 3-7: Volumes (readDouble returns NAN on failure - exactly what we want)
    double dailyVolume = parser.readDouble(3);
    double openingVolume = parser.readDouble(4);
    double closingVolume = parser.readDouble(5);
    double avgTradeSize = parser.readDouble(6);
    double avgContinuousTradeSize = parser.readDouble(7);
    
    // 8: Special day multiplier (optional)
    std::optional<double> specialDayMultiplier;
    if (parser.getCount() > 8) {
        double mult = parser.readDouble(8);
        if (!std::isnan(mult) && mult > 0.0) {
            specialDayMultiplier = mult;
        }
    }
    
    // Build ADVData
    entry.data = ADVData(
        dailyVolume: dailyVolume,
        openingVolume: openingVolume,
        closingVolume: closingVolume,
        intradayAuctionVolume: ADVData::IntradayAuctionVolumeContainer(),
        avgTradeSize: avgTradeSize,
        avgContinuousTradeSize: avgContinuousTradeSize
    );
    
    entry.specialDayMultiplier = specialDayMultiplier;
    
    return std::make_pair(std::move(key), std::move(entry));
}

/******************************************************************************
 * Create ADV Worker
 *****************************************************************************/
void CafeADVCalculator::create(const ADVSpecification& specification, ADVDynamicModel& value) {
    
    if (_csvMode) {
        // Try CSV cache first
        auto ricOpt = specification._instrument.get(type: volt::SymbolType::RIC);
        
        if (ricOpt) {
            CacheKey key{*ricOpt, specification._scope};
            auto it = _csvCache.find(key);
            
            if (it != _csvCache.end()) {
                // Cache hit - use CafeADVWorker with initial data
                const CachedADVEntry& entry = it->second;
                
                FLOG_DEBUG(_flog, StringStr() 
                    << "Cache hit: " << *ricOpt 
                    << " scope=" << (specification._scope == ADVScope::PRIMARY ? "PRIMARY" : "CONS"));
                
                // Use the new constructor with pre-loaded data
                value = new CafeADVWorker(
                    specification,
                    _mds,
                    _staticDataSource,
                    _timeManager,
                    _asyncDbPool,
                    _flog,
                    entry.data,                     // Pre-loaded ADV data
                    entry.date,                     // Date from CSV
                    entry.specialDayMultiplier);    // Special day multiplier
                return;
            }
            
            // Cache miss - log and fall through to DB
            FLOG_DEBUG(_flog, StringStr() 
                << "Cache miss, falling back to DB: " << *ricOpt 
                << " scope=" << (specification._scope == ADVScope::PRIMARY ? "PRIMARY" : "CONS"));
        }
        
        // Fall through to DB query
    }
    
    // DB query (original constructor)
    value = new CafeADVWorker(
        specification,
        _mds,
        _staticDataSource,
        _timeManager,
        _asyncDbPool,
        _flog);
}

} // namespace volt::analysis